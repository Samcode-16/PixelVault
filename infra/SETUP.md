# PixelVault v4 - AWS setup (do the phases in order)

Run every AWS console / CloudShell step as an **administrator** (root user or an admin IAM user). Your
`imageadmins` group policy only covers S3 + EC2, so it cannot create DynamoDB tables, CloudFront or SSM
parameters. (Alternative: attach `imageadmins-v4-setup-policy.json` to that group.)
Account `<YOUR_AWS_ACCOUNT_ID>` · region `ap-south-2` · bucket `<YOUR_BUCKET_NAME>`.

## Phase 1 - S3 lifecycle rule (5 min, no code)
Console: S3 -> bucket -> **Management** -> **Create lifecycle rule**
- Name `expire-old-versions`; scope **Limit to prefix `images/`**
- Tick: *Permanently delete noncurrent versions* -> **30** days, newer versions to retain **0**
- Tick: *Delete expired object delete markers or incomplete multipart uploads* -> both boxes, **7** days
- Create rule.

CloudShell alternative: upload `lifecycle.json`, then
`aws s3api put-bucket-lifecycle-configuration --bucket <YOUR_BUCKET_NAME> --lifecycle-configuration file://lifecycle.json --region ap-south-2`

Effect: "Delete forever" in the app puts a delete marker on the object; 30 days later S3 permanently removes the old
version and the marker, so storage is really freed. Rules run once a day.

## Phase 2 - DynamoDB (replaces the SQLite file)
1. CloudShell (region **Asia Pacific (Hyderabad)**): upload `create-dynamodb-table.sh`, run `bash create-dynamodb-table.sh`.
2. IAM -> Roles -> **GalleryEC2Role** -> Add permissions -> **Create inline policy** -> JSON -> paste
   `ec2-role-dynamodb-ssm-policy.json` -> name it `PixelVaultDynamoSsm`.
3. On the EC2 instance run `bash upgrade.sh` (it checks the table first, copies your SQLite data into DynamoDB,
   restarts the app). Your old `gallery.db` stays on disk untouched as a backup.
4. Check: `curl -s localhost/health` shows `"database":"dynamodb"`; log in as before - everything is still there.

## Phase 3 - CloudFront
1. **Key pair** (CloudShell):
   ```
   openssl genrsa -out pv_private.pem 2048
   openssl rsa -pubout -in pv_private.pem -out pv_public.pem
   aws ssm put-parameter --region ap-south-2 --name /pixelvault/cloudfront-private-key --type SecureString --value file://pv_private.pem
   cat pv_public.pem
   shred -u pv_private.pem
   ```
2. CloudFront -> **Key management -> Public keys -> Create**: paste `pv_public.pem`. Copy the **ID** (starts with `K`).
   Then **Key groups -> Create** `pixelvault-keys` containing that key.
3. CloudFront -> **Create distribution**: origin type **Amazon S3**, pick the bucket, leave *Origin path* empty,
   turn on **Allow private S3 bucket access to CloudFront** (creates an Origin Access Control), no WAF. Create.
4. Open the distribution -> **Behaviors** -> edit *Default*:
   viewer protocol **Redirect HTTP to HTTPS** · cache policy **CachingOptimized** · **Restrict viewer access = Yes**,
   trusted key groups -> `pixelvault-keys`. Save. (General -> Settings -> price class "Asia, Europe, North America..." is fine.)
5. **Bucket policy**: S3 -> bucket -> Permissions -> Bucket policy. Keep your existing deny-insecure statement and
   add the `AllowCloudFrontOACReadImages` statement from `bucket-policy-with-cloudfront.json`, replacing
   `REPLACE_WITH_DISTRIBUTION_ID` with the distribution ID (E...). If the console offered a "Copy policy" box, you
   may paste that instead.
6. On EC2:
   ```
   sudo sed -i '/^CDN_/d' /etc/gallery.env
   echo 'CDN_DOMAIN=dxxxxxxxxxxxx.cloudfront.net' | sudo tee -a /etc/gallery.env
   echo 'CDN_KEY_PAIR_ID=KXXXXXXXXXXXXX'        | sudo tee -a /etc/gallery.env
   sudo systemctl restart gallery && curl -s localhost/health
   ```
   `"cdn":true` means it is on. Distribution status must show *Deployed* (about 5 minutes).
7. Verify: browser DevTools -> Network: image URLs now start with your `cloudfront.net` domain. Reload: the
   response header `x-cache` becomes `Hit from cloudfront`. Opening the bare URL without `?Signature=...` returns 403.

If anything in Phase 3 breaks the app silently falls back to S3 pre-signed URLs, so the gallery never goes down.
