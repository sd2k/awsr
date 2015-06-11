context("Authentication")

headers <- list(
  "content-type" = "application/x-www-form-urlencoded; charset=utf-8",
  "x-amz-date"   = "20110909T233600Z",
  "host"         = "iam.amazonaws.com"
)
Sys.setenv(AWS_ACCESS_KEY_ID_OLD = Sys.getenv("AWS_ACCESS_KEY_ID"),
           AWS_SECRET_ACCESS_KEY_OLD = Sys.getenv("AWS_SECRET_ACCESS_KEY"))
Sys.setenv(AWS_ACCESS_KEY_ID = "AKIDEXAMPLE",
           AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")

# create_request
test_that("create_request creates the canonical request from the AWS example", {

  request <- create_request("POST", headers,
                            "Action=ListUsers&Version=2010-05-08", "/", "")
  expect_equal(
    request$hashed_canonical_request,
    "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2"
  )
})

# create_credential_scope
test_that("create_credential_scope creates the credential scope in the format AWS
          expects", {

  expect_equal(
    create_credential_scope("us-east-1", "iam", "20110909"),
    "20110909/us-east-1/iam/aws4_request"
  )
})


# create_string_to_sign
test_that("create_string_to_sign creates the same string as the AWS example", {

  request <- create_request("POST", headers,
                            "Action=ListUsers&Version=2010-05-08", "/", "")
  expect_equal(
    create_string_to_sign(
      request,
      "20110909/us-east-1/iam/aws4_request", "20110909T233600Z"
    ),
    "AWS4-HMAC-SHA256
20110909T233600Z
20110909/us-east-1/iam/aws4_request
3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2"
  )
})


# create_signing_key
test_that("create_signing_key calculates the same signing key as in the AWS
          example", {

  expect_equal(
    paste(as.integer(create_signing_key("us-east-1", "iam", "20110909")),
          collapse = " "),
    "152 241 216 137 254 196 244 66 26 220 82 43 171 12 225 248 46 105 41 194 98 237 21 229 169 76 144 239 209 227 176 231"
  )
  expect_equal(
    paste0(as.character(create_signing_key("us-east-1", "iam", "20120215")),
           collapse = ""),
    "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
  )
})


# create_auth
test_that("create_auth creates the same signatures as the AWS examples", {

  expect_equal(
    create_auth("POST", headers, "Action=ListUsers&Version=2010-05-08", "/",
                "", "20110909", "us-east-1", "iam", "20110909T233600Z"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c"
  )
})

Sys.setenv(AWS_ACCESS_KEY_ID = Sys.getenv("AWS_ACCESS_KEY_ID_OLD"),
           AWS_SECRET_ACCESS_KEY = Sys.getenv("AWS_SECRET_ACCESS_KEY_OLD"))
