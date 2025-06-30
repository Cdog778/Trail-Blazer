import boto3

dynamodb = boto3.resource('dynamodb', region_name="us-west-1")
table = dynamodb.Table('IAMBaselineProfiles')

def get_user_baseline(username):
    try:
        response = table.get_item(Key={'username': username})
        return response.get('Item')
    except Exception as e:
        print(f"[ERROR] Failed to fetch baseline for {username}: {e}")
        return None

