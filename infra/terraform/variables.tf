variable "aws_region" {
  type    = string
  default = "eu-west-1"
}

variable "project_name" {
  type    = string
  default = "honeypot-lab"
}

variable "vpc_cidr" {
  type    = string
  default = "10.50.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.50.1.0/24"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "honeypot_log_group_retention_days" {
  type    = number
  default = 14
}

variable "key_name" {
  type    = string
  default = ""
}

variable "allowed_admin_cidr" {
  type    = string
  default = ""
}

variable "enable_public_honeypot_port" {
  type    = bool
  default = true
}

variable "auto_block_enabled" {
  type    = bool
  default = true
}

variable "max_ipset_size" {
  type    = number
  default = 5000
}

variable "waf_update_max_retries" {
  type    = number
  default = 4
}
