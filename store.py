"""DynamoDB data layer for PixelVault (single-table design).

One table, keys PK + SK. Everything a user owns shares the partition  USER#<id>:
  USER#<id>  | PROFILE                 account (username, password hash, lockout state)
  USER#<id>  | IMG#<image-id>           one photo's metadata
  USER#<id>  | ALB#<album-id>           an album; its photos are a string-set attribute `image_ids`
  USER#<id>  | SHR#<image-id>#<token>   a share link (views, expiry, revoked)
Lookup items:
  USERNAME#<lowercase name> | CLAIM     guarantees unique usernames (conditional write)
  SHARE#<token>             | POINTER   token -> (user, image) so /s/<token> needs no login
Share items carry a `ttl` attribute so DynamoDB deletes them itself after they expire.
"""
import time
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

_table = None


def init(table_name, region):
    global _table
    _table = boto3.resource("dynamodb", region_name=region).Table(table_name)


def _py(v):
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, dict):
        return {k: _py(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_py(x) for x in v]
    if isinstance(v, set):
        return sorted(_py(x) for x in v)
    return v


def _query(pk, prefix):
    kw = {"KeyConditionExpression": Key("PK").eq(pk) & Key("SK").begins_with(prefix)}
    out = []
    while True:
        r = _table.query(**kw)
        out += r["Items"]
        if "LastEvaluatedKey" not in r:
            return [_py(i) for i in out]
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


def _failed_condition(err):
    return err.response["Error"]["Code"] == "ConditionalCheckFailedException"


def _update(key, set_=None, remove=(), add=None, delete=None, must_exist=True):
    names, values, sets, rem = {}, {}, [], []
    for n, (k, v) in enumerate((set_ or {}).items()):
        names[f"#s{n}"], values[f":s{n}"] = k, v
        sets.append(f"#s{n} = :s{n}")
    for n, k in enumerate(remove):
        names[f"#r{n}"] = k
        rem.append(f"#r{n}")
    parts = []
    if sets: parts.append("SET " + ", ".join(sets))
    if rem: parts.append("REMOVE " + ", ".join(rem))
    for word, spec in (("ADD", add), ("DELETE", delete)):
        if spec:
            (k, v), = spec.items()
            names["#a"], values[":a"] = k, v
            parts.append(f"{word} #a :a")
    kw = {"Key": key, "UpdateExpression": " ".join(parts), "ExpressionAttributeNames": names}
    if values: kw["ExpressionAttributeValues"] = values
    if must_exist: kw["ConditionExpression"] = "attribute_exists(PK)"
    try:
        _table.update_item(**kw)
        return True
    except ClientError as e:
        if _failed_condition(e):
            return False
        raise


# ------------------------------------------------------------------ users ----
def create_user(uid, username, pw_hash, created_at=None):
    """Returns False if the username is taken (conditional write = atomic uniqueness check)."""
    try:
        _table.put_item(Item={"PK": f"USERNAME#{username.lower()}", "SK": "CLAIM", "user_id": uid},
                        ConditionExpression="attribute_not_exists(PK)")
    except ClientError as e:
        if _failed_condition(e):
            return False
        raise
    _table.put_item(Item={"PK": f"USER#{uid}", "SK": "PROFILE", "id": uid, "username": username, "pw_hash": pw_hash,
                          "created_at": created_at or int(time.time()), "failed_count": 0, "locked_until": 0})
    return True


def get_user(uid):
    if not isinstance(uid, str):
        return None
    item = _table.get_item(Key={"PK": f"USER#{uid}", "SK": "PROFILE"}).get("Item")
    return _py(item) if item else None


def get_user_by_name(username):
    claim = _table.get_item(Key={"PK": f"USERNAME#{username.lower()}", "SK": "CLAIM"}).get("Item")
    return get_user(claim["user_id"]) if claim else None


def set_login_state(uid, failed, locked_until):
    _update({"PK": f"USER#{uid}", "SK": "PROFILE"}, {"failed_count": failed, "locked_until": locked_until})


# ----------------------------------------------------------------- images ----
def list_images(uid):
    return _query(f"USER#{uid}", "IMG#")


def get_image(uid, image_id):
    item = _table.get_item(Key={"PK": f"USER#{uid}", "SK": f"IMG#{image_id}"}).get("Item")
    return _py(item) if item else None


def put_image(uid, img):
    item = {k: v for k, v in img.items() if v is not None}
    item.update(PK=f"USER#{uid}", SK=f"IMG#{img['id']}", user_id=uid)
    _table.put_item(Item=item)


def update_image(uid, image_id, set_=None, remove=()):
    return _update({"PK": f"USER#{uid}", "SK": f"IMG#{image_id}"}, set_, remove)


def delete_images(uid, ids):
    with _table.batch_writer() as batch:
        for i in ids:
            batch.delete_item(Key={"PK": f"USER#{uid}", "SK": f"IMG#{i}"})


def scan_images():
    """Every image of every user (admin CLI only)."""
    kw, out = {"FilterExpression": Attr("SK").begins_with("IMG#")}, []
    while True:
        r = _table.scan(**kw)
        out += r["Items"]
        if "LastEvaluatedKey" not in r:
            return [_py(i) for i in out]
        kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]


# ----------------------------------------------------------------- albums ----
def list_albums(uid):
    return _query(f"USER#{uid}", "ALB#")


def get_album(uid, album_id):
    if not isinstance(album_id, str):
        return None
    item = _table.get_item(Key={"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}).get("Item")
    return _py(item) if item else None


def create_album(uid, album_id, name, created_at=None):
    _table.put_item(Item={"PK": f"USER#{uid}", "SK": f"ALB#{album_id}", "id": album_id, "name": name,
                          "created_at": created_at or int(time.time())})


def rename_album(uid, album_id, name):
    return _update({"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}, {"name": name})


def delete_album(uid, album_id):
    _table.delete_item(Key={"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"})


def album_add(uid, album_id, ids):
    if ids:
        _update({"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}, add={"image_ids": set(ids)})


def album_remove(uid, album_id, ids):
    if ids:                                       # DynamoDB drops the attribute itself when the set becomes empty
        _update({"PK": f"USER#{uid}", "SK": f"ALB#{album_id}"}, delete={"image_ids": set(ids)})


def strip_from_albums(uid, ids):
    gone = set(ids)
    for a in list_albums(uid):
        hit = gone & set(a.get("image_ids", []))
        if hit:
            album_remove(uid, a["id"], hit)


# ----------------------------------------------------------------- shares ----
def create_share(token, uid, image_id, expires_at, created_at=None, views=0):
    ttl = expires_at + 86400
    _table.put_item(Item={"PK": f"USER#{uid}", "SK": f"SHR#{image_id}#{token}", "token": token, "image_id": image_id,
                          "user_id": uid, "created_at": created_at or int(time.time()), "expires_at": expires_at,
                          "revoked": False, "views": views, "ttl": ttl})
    _table.put_item(Item={"PK": f"SHARE#{token}", "SK": "POINTER", "user_id": uid, "image_id": image_id, "ttl": ttl})


def get_share(token):
    p = _table.get_item(Key={"PK": f"SHARE#{token}", "SK": "POINTER"}).get("Item")
    if not p:
        return None
    s = _table.get_item(Key={"PK": f"USER#{p['user_id']}", "SK": f"SHR#{p['image_id']}#{token}"}).get("Item")
    return _py(s) if s else None


def bump_views(share):
    _update({"PK": f"USER#{share['user_id']}", "SK": f"SHR#{share['image_id']}#{share['token']}"}, add={"views": 1})


def list_shares(uid, image_id):
    return _query(f"USER#{uid}", f"SHR#{image_id}#")


def revoke_share(uid, token):
    p = _table.get_item(Key={"PK": f"SHARE#{token}", "SK": "POINTER"}).get("Item")
    if not p or p["user_id"] != uid:
        return False
    return _update({"PK": f"USER#{uid}", "SK": f"SHR#{p['image_id']}#{token}"}, {"revoked": True})


def revoke_image_shares(uid, image_id):
    for s in list_shares(uid, image_id):
        if not s["revoked"]:
            _update({"PK": f"USER#{uid}", "SK": f"SHR#{image_id}#{s['token']}"}, {"revoked": True})
