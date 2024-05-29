variable "bucket" {
  type    = string
  default = "terraform-state"
}

variable "key" {
  type    = string
  default = "terraform.tfstate"
}

variable "dynamodb_table" {
  type    = string
  default = "terraform-state"
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "aws_account" {
  type    = string
  default = "############"
}

variable "FRONTEND_BUCKET" {
  type    = string
  default = "frontend-bucket"
}

variable "LOGGING_BUCKET" {
  type    = string
  default = "logging-bucket"
}
