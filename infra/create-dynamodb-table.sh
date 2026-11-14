#!/bin/bash
# Run once in AWS CloudShell (region ap-south-2) with an admin identity.
set -euo pipefail
REGION=ap-south-2
TABLE=PixelVault
aws dynamodb create-table --region $REGION --table-name $TABLE \
  --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
  --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST
aws dynamodb wait table-exists --region $REGION --table-name $TABLE
# let DynamoDB delete expired share links by itself
aws dynamodb update-time-to-live --region $REGION --table-name $TABLE \
  --time-to-live-specification Enabled=true,AttributeName=ttl
# point-in-time recovery: restore the table to any second in the last 35 days
aws dynamodb update-continuous-backups --region $REGION --table-name $TABLE \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
echo "Table $TABLE ready."
