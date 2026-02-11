output "honeypot_public_ip" {
  value = aws_instance.honeypot.public_ip
}

output "cloudwatch_log_group" {
  value = aws_cloudwatch_log_group.honeypot.name
}

output "vpc_id" {
  value = aws_vpc.hp.id
}
