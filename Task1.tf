provider "aws"{
	region="ap-south-1"
  	profile = "VinujaKhatode"
}

//Creating KEY

resource "tls_private_key" "tls_key" {
  	algorithm = "RSA"
}

//Generating Key-Value Pair

resource "aws_key_pair" "generated_key" {
  	key_name = "Task1keyvin"
  	public_key ="${tls_private_key.tls_key.public_key_openssh}"
  	
	depends_on = [
    		tls_private_key.tls_key
  	]
}


//Saving Private KEY PEM File

resource "local_file" "key-file" {
  	content  = "${tls_private_key.tls_key.private_key_pem}"
  	filename = "Task1keyvin.pem"

  	depends_on = [
    		tls_private_key.tls_key,
		aws_key_pair.generated_key
 	]
}


//Creating Security Group

resource "aws_security_group" "Task1sec" {
  	name        = "Task1sec"
  	description = "Security Group for Task1 SSH and HTTPD"


//Adding Rules to Security Group 

  	ingress {
    		description = "SSH Port"
    		from_port   = 22
    		to_port     = 22
    		protocol    = "tcp"
    		cidr_blocks = ["0.0.0.0/0"]
  	}
  	ingress {
    		description = "HTTP Port"
    		from_port   = 80
    		to_port     = 80
    		protocol    = "tcp"
    		cidr_blocks = ["0.0.0.0/0"]
  	}
	ingress {
		description = "Localhost"
		from_port = 8080
		to_port = 8080
		protocol = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
}
	egress {
		from_port   = 0
		to_port     = 0
		protocol    = "-1"
		cidr_blocks = ["0.0.0.0/0"]
	}
	tags = {
		Name = "Task1sec"
	}
}

// Creating instance with above created key and security group

resource "aws_instance" "Task1instance" {
	ami = "ami-005956c5f0f757d37"
	instance_type = "t2.micro"
	key_name = "${aws_key_pair.generated_key.key_name}"
	security_groups = ["${aws_security_group.Task1sec.name}"]
	tags = {
		Name = "Task1instance" 
	}
}

// Creating new EBS Volume and attachin it to the above created instance

resource "aws_ebs_volume" "ebs1" {
  	availability_zone = aws_instance.Task1instance.availability_zone
  	size = 1
 	tags = {
    		Name = "Task1ebs"
  	}
}

// To attach the Volume created
resource "aws_volume_attachment" "ebs_attach" {
  	device_name = "/dev/sdh"
  	volume_id   = "${aws_ebs_volume.ebs1.id}"
  	instance_id = "${aws_instance.Task1instance.id}"
  	force_detach = true
}

// For Output

output "myos_ip" {
  value = aws_instance.Task1instance.public_ip
}

// In order to use Volume partition, format nad mounting is necessary

resource "null_resource" "nullremote"  {

depends_on = [
    	aws_volume_attachment.ebs_attach,
	aws_security_group.Task1sec,
   	aws_key_pair.generated_key	
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = file("C:/Users/vinuja khatode/VWorkspace/Terraform/Task1/Task1keyvin.pem")
    host     = aws_instance.Task1instance.public_ip
  }

provisioner "remote-exec" {
    inline = [
     	"sudo yum install httpd  php git -y",
      	"sudo service httpd start",
     	"sudo chkconfig httpd on",	
      	"sudo mkfs.ext4  /dev/xvdh",
      	"sudo mount  /dev/xvdh  /var/www/html",
      	"sudo rm -rf /var/www/html/*",
      	"sudo git clone https://github.com/vinujakhatode/Webserver-Terraform-AWS.git  /var/www/html/"
    ]
  }
}


// Creating S3 bucket

resource "aws_s3_bucket" "task1bucketvinuja00vinuja00" {
	bucket = "task1bucketvinuja00vinuja00"
	acl    = "private"
	tags = {
		Name = "task1bucketvinuja00vinuja00"
	}
}

// Allow Public Access

resource "aws_s3_bucket_public_access_block" "S3PublicAccess" {
	bucket = "${aws_s3_bucket.task1bucketvinuja00vinuja00.id}"
	block_public_acls   = true
	block_public_policy = true
	restrict_public_buckets = true
}

// Uploading files to S3 bucket

resource "aws_s3_bucket_object" "bucketObject" {
	for_each = fileset("C:/Users/vinuja khatode/Desktop/girly/assets", "**/*.jpg")
	bucket = "${aws_s3_bucket.task1bucketvinuja00vinuja00.bucket}"
	key    = each.value
	source = "C:/Users/vinuja khatode/Desktop/girly/assets/${each.value}"
	content_type = "image/jpg"
}


//Creating Cloudfront to access images from S3

locals {
	s3_origin_id = "S3Origin"
}


// Creating Origin Access Identity for CloudFront

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
	comment = "task1bucketvinuja00vinuja00"
}

resource "aws_cloudfront_distribution" "Task1CF" {

origin {
	domain_name = "${aws_s3_bucket.task1bucketvinuja00vinuja00.bucket_regional_domain_name}"
	origin_id = "${local.s3_origin_id}"
	s3_origin_config {
		origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
	}
}

	enabled = true
	is_ipv6_enabled = true
	comment = "accessforTask1"
	default_cache_behavior {
		allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
		cached_methods = ["GET", "HEAD"]
		target_origin_id = "${local.s3_origin_id}"
		forwarded_values {
			query_string = false
			cookies {
				forward = "none"
			}
		}
		viewer_protocol_policy = "allow-all"
		min_ttl = 0
		default_ttl = 3600
		max_ttl = 86400
	}
// Cache behavior with precedence 0

	ordered_cache_behavior {
	path_pattern = "/content/immutable/*"
	allowed_methods = ["GET", "HEAD", "OPTIONS"]
	cached_methods = ["GET", "HEAD", "OPTIONS"]
	target_origin_id = "${local.s3_origin_id}"
	forwarded_values {
		query_string = false
		headers = ["Origin"]
		cookies {
			forward = "none"
		}
	}

	min_ttl = 0
	default_ttl = 86400
	max_ttl = 31536000
	compress = true
	viewer_protocol_policy = "redirect-to-https"
}
// Cache behavior with precedence 1
ordered_cache_behavior {
	path_pattern = "/content/*"
	allowed_methods = ["GET", "HEAD", "OPTIONS"]
	cached_methods = ["GET", "HEAD"]
	target_origin_id = "${local.s3_origin_id}"
	forwarded_values {
		query_string = false
		cookies {
			forward = "none"
		}
	}
min_ttl = 0
default_ttl = 3600
max_ttl = 86400
compress = true
viewer_protocol_policy = "redirect-to-https"
}
price_class = "PriceClass_200"
restrictions {
geo_restriction {
restriction_type = "whitelist"
locations = ["IN"]
}
}
tags = {
Name="Task1CFDistribution"
Environment = "production"
}
viewer_certificate {
cloudfront_default_certificate = true
}
retain_on_delete = true

depends_on=[
	aws_s3_bucket.task1bucketvinuja00vinuja00
]
}

// AWS Bucket Policy for CloudFront
data "aws_iam_policy_document" "s3_policy" {
statement {
actions   = ["s3:GetObject"]
resources = ["${aws_s3_bucket.task1bucketvinuja00vinuja00.arn}/*"]
principals {
type        = "AWS"
identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
}
}
statement {
actions   = ["s3:ListBucket"]
resources = ["${aws_s3_bucket.task1bucketvinuja00vinuja00.arn}"]
principals {
type        = "AWS"
identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
}
}
}
resource "aws_s3_bucket_policy" "s3BucketPolicy" {
bucket = "${aws_s3_bucket.task1bucketvinuja00vinuja00.id}"
policy = "${data.aws_iam_policy_document.s3_policy.json}"
}