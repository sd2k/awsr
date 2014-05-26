require(httr)
require(RCurl)
require(stringr)

aws_key = function() 'AKIAJGE7TQU3PDEGGGGQ' #Sys.getenv('AWS_KEY')
aws_secret = function() {
  #Sys.getenv('AWS_SECRET_KEY')
  return('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')
}

# Miscellaneous functions to format time and date
now <- function() format(lubridate::now(), '%Y%m%dT%H%M%SZ')
today <- function() format(lubridate::today(), '%Y%m%d')

request_date = now()

#' Reorder a query and URI encode the parameter names and values
construct_query <- function(query) {
  
  # Split query on '&' and '='
  split_query <- str_split(str_split(query, pattern='&')[[1]], pattern = '=')
  query_df <- do.call(rbind, split_query)
  
  # URI encode strings
  query_df <- apply(query_df, 2, curlEscape)
  
  # Need to change locale to ensure the sort is on ASCII value
  old_locale <- Sys.getlocale("LC_COLLATE")
  Sys.setlocale("LC_COLLATE", "C")
  if(!is.matrix(query_df)){
    return(str_c(query_df[1], "=", query_df[2]))
  }
  query_df <- query_df[order(query_df[,1]),]
  Sys.setlocale("LC_COLLATE", old_locale)
  return(str_c(query_df[,1], "=", query_df[,2], collapse="&"))
}

#' Create a canonical request and hashed canonical request.
#' 
#' This function puts together an http request into a standardised (canonical) form,
#' to ensure that the signature calculated by AWS when it receives the request
#' matches the one calculated by us. This is the equivalent of Task 1 in the AWS
#' API Signature Version 4 signing process
#' (http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html).
#' @param request_method the HTTP verb used for the request (GET/POST/PUT etc)
#' @param headers list of headers to be included in the request. Must include a 
#'  \code{host} header. See examples for correct format
#' @param payload the payload from the body of the HTTP/HTTPS request
#' @param uri the absolute path component of the uri
#' @param query the query string of the request. May be empty if the query is in
#'  the payload instead (the default)
#' @examples
#' headers <- list(
#'    'content-type' = 'application/x-www-form-urlencoded; charset=utf-8',
#'    'x-amz-date'   = '20110909T233600Z',
#'    'host'         = 'iam.amazonaws.com') 
#' create_request('POST', headers, 'Action=ListUsers&Version=2010-05-08', '/', '')

create_request = function(request_method, headers, payload,
                          uri = '/', query = '') {
  # Only encode query if it's given
  if (query != ''){
    query <- construct_query(query)
  }
  
  # Canonicalise the headers
  headers <- headers[order(names(headers))]
  names(headers) <- tolower(names(headers))
  canonical_headers <- str_c(names(headers), ':', unlist(headers), collapse = '\n')
  canonical_headers <- str_c(canonical_headers, '\n')
  
  signed_headers <- str_c(names(headers), collapse = ';')
  
  hashed_payload = digest::digest(payload, algo="sha256", serialize = FALSE)
  
  canonical_request = str_c(request_method, '\n',
                            uri, '\n',
                            query, '\n',
                            canonical_headers, '\n',
                            signed_headers, '\n',
                            hashed_payload)
  hashed_canonical_request = digest::digest(canonical_request, algo="sha256", serialize = FALSE)
  out <- list(canonical_request = canonical_request,
              hashed_canonical_request = hashed_canonical_request,
              signed_headers = signed_headers)
  return(out)
}

#' Create the credential scope string.
#' 
#' Helper function for concatenating strings into the right format for the
#' credential scope value.
#' @param date_stamp date in the form YYYYMMDD - must match that used in other 
#'  steps
#' @param region region being targeted
#' @param service being targeted
#' @examples
#' credential_scope('20110909', 'us-east-1', 'iam')
create_credential_scope = function(date_stamp = date_stamp, region, service) {
  str_c(date_stamp, region, service, 'aws4_request', sep = "/")
}

#' Create a string to sign.
#' 
#' This function is the equivalent of Task 2 in the AWS API Signature Version 4
#' signing process
#' (http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html).
#' It currently only uses SHA256; this can be easily changed in future if 
#' necessary. 
#' 
#' @param hashed_canonical_request hashed canonical request passed on from 
#'   create_request
#' @param credential_scope credential_scope string calculated by the function
#'  of the same name
#' @param request_date string containing the date and time of the request,
#'  matching the value used in previous steps, in the form YYYYMMDDTHHMMSSZ
#' @examples
#' create_string_to_sign('3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2',
#'                '20110909/us-east-1/iam/aws4_request\n',
#'                '20110909T233600Z\n')

create_string_to_sign = function(full_canonical_request, 
                          credential_scope,
                          request_date = request_date) {
  str_c('AWS4-HMAC-SHA256\n',
        request_date, '\n',
        credential_scope, '\n',
        full_canonical_request$hashed_canonical_request)
}

#' Calculate the signing key.
#' 
#' This function is the equivalent of Task 3 in the AWS API Signature Version 4
#' signing process 
#' (http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html).
#' It currently only uses SHA256; this can be easily changed in future if 
#' necessary.
#' 
#' @param date_stamp request date in the form YYYYMMDD; defaults to the current 
#'  date. This must match the date used in the credential scope when creating 
#'  the string to sign
#' @param region_name name of the AWS region being targeted, e.g. 'eu-west-1'
#' @param service_name name of the AWS service being targeted, e.g. 'ec2'
#' @examples
#' create_signing_key('20120215', 'us-east-1', 'iam')
create_signing_key = function(date_stamp = today(), region_name, service_name) {
  key_date = digest::hmac(str_c('AWS4', aws_secret()), date_stamp, algo = 'sha256', raw = TRUE)
  key_region = digest::hmac(key_date, region_name, algo = 'sha256', raw = TRUE)
  key_service = digest::hmac(key_region, service_name, algo = 'sha256', raw = TRUE)
  key_signing = digest::hmac(key_service, 'aws4_request', algo = 'sha256', raw = TRUE)
  key_signing
}

#' Create the final signature to be added to the HTTP header as Authorization.
#' 
#' This is the final step in the authorization procedure, where the three tasks
#' are put together to create the authorization value.
#' @param request_method the HTTP verb used for the request (GET/POST/PUT etc)
#' @param headers list of headers to be included in the request. Must include a 
#'  \code{host} header. See examples for correct format
#' @param payload the payload from the body of the HTTP/HTTPS request
#' @param uri
#' @param query
#' @param date_stamp request date in the form YYYYMMDD; defaults to the current 
#'  date.
#' @param region_name name of the AWS region being targeted, e.g. 'eu-west-1'
#' @param service_name name of the AWS service being targeted, e.g. 'ec2'
#' @param request_date string containing the date and time of the request,
#'  matching the value used in previous steps, in the form YYYYMMDDTHHMMSSZ
#' @examples
#' headers <- list(
#'    'content-type' = 'application/x-www-form-urlencoded; charset=utf-8',
#'    'x-amz-date'   = '20110909T233600Z',
#'    'host'         = 'iam.amazonaws.com')
#' create_auth('POST', headers, 'Action=ListUsers&Version=2010-05-08', '/',
#'                  '', '20110909', 'us-east-1', 'iam', '20110909T233600Z')
#' create_auth('GET',
#'                  list('Date'='Mon, 09 Sep 2011 23:36:00 GMT','Host'='host.foo.com'),
#'                  '', '/', 'foo=Zoo&foo=aha', '20110909', 'us-east-1', 'host',
#'                  '20110909T233600Z')
create_auth <- function(request_method, headers, payload, uri, query,
                            date_stamp, region_name, service_name, 
                            request_date) {  
  
  full_request <- create_request(request_method, headers, payload, uri, query)
  
  credential_scope <- create_credential_scope(date_stamp, region_name, service_name)
  string_to_sign <- create_string_to_sign(full_request, credential_scope, request_date)

  signing_key <- create_signing_key(date_stamp, region_name, service_name)
  
  signature <- digest::hmac(signing_key, string_to_sign, algo="sha256")
  
  auth <- str_c('AWS4-HMAC-SHA256 Credential=', aws_key(), '/', 
                credential_scope, ', SignedHeaders=',
                full_request$signed_headers, ", Signature=", signature)
  out <- add_headers(Authorization = auth)
}
