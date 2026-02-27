data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-sg"
  description = "Security group for ${var.name_prefix} instances"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "evident_framework" {
  security_group_id = aws_security_group.this.id
  type = "ingress"
  from_port = 5000
  to_port = 5010 # TODO: squeeze to actually needed port(s)
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "debug_ssh" {
  security_group_id = aws_security_group.this.id
  type = "ingress"
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
