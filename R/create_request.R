aws_key = Sys.getenv("AWS_KEY")
aws_secret = Sys.getenv("AWS_SECRET_KEY")

create_request = function(payload,
                          method = 'GET',
                          uri = '/',
                          query_string = '',
                          headers = list('content-type',
                                         'host',
                                         'x-amz-date'),
                          signed_headers = str_c('content_type;',
                                                 'host;',
                                                 'x-amz-date')) {
}

string_to_sign = function(hashed_canonical_request, 
                          credential_scope,
                          request_date = today(),
                          algorithm = 'AWS4-HMAC-SHA256') {
  str_c(algorithm, '\n',
        request_date, '\n',
        credential_scope, '\n',
        hashed_canonical_request)
}
add_headers(method = "GET")
# Function to create the signing key used to calculate the final signature
signing_key = function(key=aws_secret, date_stamp, region_name, service_name) {
  key_date = digest::hmac(str_c('AWS4', key), date_stamp, algo = 'sha256', raw = TRUE)
  key_region = digest::hmac(key_date, region_name, algo = 'sha256', raw = TRUE)
  key_service = digest::hmac(key_region, service_name, algo = 'sha256', raw = TRUE)
  key_signing = digest::hmac(key_service, 'aws4_request', algo = 'sha256', raw = TRUE)
  
  key_signing
}

# Miscellaneous functions to format time and date
now <- function() format(lubridate::now(), '%Y%m%dT%H%M%SZ')
today <- function() format(lubridate::today(), '%Y%m%d')