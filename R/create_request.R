
auth_header = function() {
  
}

create_request = function(method = "GET",
                                    uri = "/",
                                    querystring = "",
                                    headers = list('content-type',
                                                   'application',
                                    ),  ) {
}

# Function to create the signing key used to calculate the final signature
signing_key = function(key, date_stamp, region_name, service_name) {
  key_date = digest::hmac(str_c("AWS4", key), date_stamp, algo = "sha256", raw = TRUE)
  key_region = digest::hmac(key_date, region_name, algo = "sha256", raw = TRUE)
  key_service = digest::hmac(key_region, service_name, algo = "sha256", raw = TRUE)
  key_signing = digest::hmac(key_service, "aws4_request", algo = "sha256", raw = TRUE)
  
  key_signing
}

# Miscellaneous functions to format time and date
now <- function() format(lubridate::now(), "%Y%m%dT%H%M%SZ")
today <- function() format(lubridate::today(), "%Y%m%d")
