import requests
import random
from flask import Flask, jsonify, request
from datetime import datetime, timedelta, timezone

class GameInfo:
    def __init__(self):
        self.TitleId = "151F21"
        self.SecretKey = "EAOZNIRN4F3X778GYR6QB13CS6Q5KAQOXON9GRGDZOHJZOSKE4"
        self.ApiKey = "OC|31213118338334218|51448a05954fa18aca21b62aa58f0416"

    def GetAuthHeaders(self) -> dict:
        return {
            "content-type": "application/json",
            "X-SecretKey": self.SecretKey
        }

    def GetTitle(self) -> str:
        return self.TitleId

settings = GameInfo()
app = Flask(__name__)
playfabCache = {}
muteCache = {}

settings.TitleId = ""
settings.SecretKey = ""
settings.ApiKey = ""

def ReturnFunctionJson(data, funcname, funcparam={}):
    rjson = data.get("FunctionParameter", {})
    userId = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("TitlePlayerAccountId")

    req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/ExecuteCloudScript",
        json={
            "PlayFabId": userId,
            "FunctionName": funcname,
            "FunctionParameter": funcparam
        },
        headers=settings.GetAuthHeaders()
    )

    if req.status_code == 200:
        return jsonify(req.json().get("data").get("FunctionResult")), req.status_code
    else:
        return jsonify({}), req.status_code

def GetIsNonceValid(nonce: str, oculusId: str):
    req = requests.post(
        url=f'https://graph.oculus.com/user_nonce_validate?nonce={nonce}&user_id={oculusId}&access_token={settings.ApiKey}',
        headers={
            "content-type": "application/json"
        }
    )
    return req.json().get("is_valid")

@app.route("/", methods=["POST", "GET"])
def main():
    return "it workie"

@app.route("/api/PlayFabAuthentication", methods=["POST", "GET"])
def playfabauthentication():
    rjson = request.get_json()

    if rjson.get("CustomId") is None:
        return jsonify({"Message": "Missing CustomId parameter", "Error": "BadRequest-NoCustomId"})
    if rjson.get("Nonce") is None:
        return jsonify({"Message": "Missing Nonce parameter", "Error": "BadRequest-NoNonce"})
    if rjson.get("AppId") is None:
        return jsonify({"Message": "Missing AppId parameter", "Error": "BadRequest-NoAppId"})
    if rjson.get("Platform") is None:
        return jsonify({"Message": "Missing Platform parameter", "Error": "BadRequest-NoPlatform"})
    if rjson.get("OculusId") is None:
        return jsonify({"Message": "Missing OculusId parameter", "Error": "BadRequest-NoOculusId"})

    if rjson.get("AppId") != settings.TitleId:
        return jsonify({"Message": "Request sent for the wrong App ID", "Error": "BadRequest-AppIdMismatch"})
    if not rjson.get("CustomId").startswith("OC") and not rjson.get("CustomId").startswith("PI"):
        return jsonify({"Message": "Bad request", "Error": "BadRequest-No OC or PI Prefix"})

    if rjson.get("Platform") == "Windows":
        return jsonify({"Message": "scary hacker", "Error": "Forbidden-Platform"}), 403
    

    custom_id = rjson.get("CustomId")
    if custom_id == "OCULUS0":
        ban_req = requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Admin/BanUsers",
            json={
                "Bans": [
                    {
                        "PlayFabId": rjson.get("currentPlayerId"),
                        "DurationInHours": None, 
                        "Reason": "CHEATING."
                    }
                ]
            },
            headers=settings.GetAuthHeaders()
        )
        if ban_req.status_code == 200:
            return jsonify({"Message": "bro was banned for: Lemonloader", "Error": "Banned"}), 403
        else:
            return jsonify({"Message": "Failed to ban user", "Error": "InternalError"}), 500

    url = f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId"
    login_request = requests.post(
        url=url,
        json={
            "ServerCustomId": custom_id,
            "CreateAccount": True
        },
        headers=settings.GetAuthHeaders()
    )

    if login_request.status_code == 200:
        data = login_request.json().get("data")
        sessionTicket = data.get("SessionTicket")
        entityToken = data.get("EntityToken").get("EntityToken")
        playFabId = data.get("PlayFabId")
        entityType = data.get("EntityToken").get("Entity").get("Type")
        entityId = data.get("EntityToken").get("Entity").get("Id")

        print(requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Client/LinkCustomID",
            json={
                "ForceLink": True,
                "CustomId": custom_id
            },
            headers=settings.GetAuthHeaders()
        ).json())

        return jsonify({
            "PlayFabId": playFabId,
            "SessionTicket": sessionTicket,
            "EntityToken": entityToken,
            "EntityId": entityId,
            "EntityType": entityType
        })
    else:
        if login_request.status_code == 403:
            ban_info = login_request.json()
            if ban_info.get('errorCode') == 1002:
                ban_message = ban_info.get('errorMessage', "No ban message provided.")
                ban_details = ban_info.get('errorDetails', {})
                ban_expiration_key = next(iter(ban_details.keys()), None)
                ban_expiration_list = ban_details.get(ban_expiration_key, [])
                ban_expiration = ban_expiration_list[0] if len(ban_expiration_list) > 0 else "No expiration date provided."
                print(ban_info)
                return jsonify({
                    'BanMessage': ban_expiration_key,
                    'BanExpirationTime': ban_expiration
                }), 403
            else:
                error_message = ban_info.get('errorMessage', 'Forbidden without ban information.')
                return jsonify({
                    'Error': 'PlayFab Error',
                    'Message': error_message
                }), 403
        else:
            error_info = login_request.json()
            error_message = error_info.get('errorMessage', 'An error occurred.')
            return jsonify({
                'Error': 'PlayFab Error',
                'Message': error_message
            }), login_request.status_code

@app.route("/api/CachePlayFabId", methods=["POST", "GET"])
def cacheplatfabid():
    rjson = request.get_json()

    playfabCache[rjson.get("PlayFabId")] = rjson

    return jsonify({"Message": "Success"}), 200

@app.route('/api/TitleData', methods=['POST'])
def titled_data():
    return jsonify({"MOTD": "pp"})

@app.route("/api/CheckForBadName", methods=["POST", "GET"])
def checkforbadname():
    rjson = request.get_json()
    function_result = rjson["FunctionArgument"]
    playfab_id = rjson["CallerEntityProfile"]["Lineage"]["MasterPlayerAccountId"]
    name = function_result["name"].upper()
    forRoom = function_result["forRoom"]

    if forRoom == True:
        return jsonify({"result": 0})

    link_response = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Admin/UpdateUserTitleDisplayName",
        json={
            "DisplayName": name,
            "PlayFabId": playfab_id,
        },
        headers=settings.GetAuthHeaders(),
    ).json()
    return jsonify({"result": 0})

@app.route("/api/GetAcceptedAgreements", methods=['POST', 'GET'])
def GetAcceptedAgreements():
    data = request.json

    return jsonify({"PrivacyPolicy": "1.1.67", "TOS": "11.05.22.2"}), 200

@app.route("/api/SubmitAcceptedAgreements", methods=['POST', 'GET'])
def SubmitAcceptedAgreements():
    data = request.json

    return jsonify({"PrivacyPolicy": "1.1.67", "TOS": "11.05.22.2"}), 200

@app.route('/api/GetName', methods=['POST', 'GET'])
def GetName():
    return jsonify({"result": f"GORILLA{random.randint(1000,9999)}"})

@app.route("/api/ConsumeOculusIAP", methods=["POST", "GET"])
def consumeoculusiap():
    rjson = request.get_json()

    accessToken = rjson.get("userToken")
    userId = rjson.get("userID")
    playFabId = rjson.get("playFabId")
    nonce = rjson.get("nonce")
    platform = rjson.get("platform")
    sku = rjson.get("sku")
    debugParams = rjson.get("debugParemeters")

    req = requests.post(
        url=f"https://graph.oculus.com/consume_entitlement?nonce={nonce}&user_id={userId}&sku={sku}&access_token={settings.ApiKey}",
        headers={
            "content-type": "application/json"
        }
    )

    if bool(req.json().get("success")):
        return jsonify({"result": True})
    else:
        return jsonify({"error": True})

@app.route("/api/ReturnMyOculusHashV2")
def returnmyoculushashv2():
    return ReturnFunctionJson(request.get_json(), "ReturnMyOculusHash")

@app.route("/api/ReturnCurrentVersionV2", methods=["POST", "GET"])
def returncurrentversionv2():
    return ReturnFunctionJson(request.get_json(), "ReturnCurrentVersion")

@app.route("/api/TryDistributeCurrencyV2", methods=["POST"])
def TryDistributeCurrencyV2():
    if request.method != "POST":
        return "", 404

    rjson = request.json
    sr_a_day = 500  # You can change, I don't really care.
    current_player_id = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("MasterPlayerAccountId")

    get_data_response = requests.post(
        f"https://{settings.TitleId}.playfabapi.com/Server/GetUserReadOnlyData",
        headers=settings.GetAuthHeaders(),
        json={
            "PlayFabId": current_player_id,
            "Keys": ["DailyLogin"]
        }
    )

    daily_login_value = get_data_response.json().get("data").get("Data").get("DailyLogin", {}).get("Value", None)

    last_login_date = None
    if daily_login_value:
        last_login_date = datetime.fromisoformat(daily_login_value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    if not last_login_date or last_login_date < datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc):
        requests.post(
            f"https://{settings.TitleId}.playfabapi.com/Server/AddUserVirtualCurrency",
            headers=settings.GetAuthHeaders(),
            json={
                "PlayFabId": current_player_id,
                "VirtualCurrency": "SR",
                "Amount": sr_a_day
            }
        )

        requests.post(
            f"https://{settings.TitleId}.playfabapi.com/Server/UpdateUserReadOnlyData",
            headers=settings.GetAuthHeaders(),
            json={
                "PlayFabId": current_player_id,
                "Data": {
                    "DailyLogin": datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc).isoformat()
                }
            }
        )

    return "", 200

@app.route("/api/BroadCastMyRoomV2", methods=["POST", "GET"])
def broadcastmyroomv2():
    return ReturnFunctionJson(request.get_json(), "BroadCastMyRoom", request.get_json()["FunctionParameter"])

@app.route("/api/ShouldUserAutomutePlayer", methods=["POST", "GET"])
def shoulduserautomuteplayer():
    return jsonify(muteCache)
# Photon Authentication by ires.
@app.route("/api/photon", methods=["POST"])
def photonauth():
    print(f"Received {request.method} at /api/photon")
    getjson = request.get_json()
    Ticket = getjson.get("Ticket")
    Nonce = getjson.get("Nonce")
    Platform = getjson.get("Platform")
    UserId = getjson.get("UserId")
    nickName = getjson.get("username")
    if request.method.upper() == "GET":
        rjson = request.get_json()
        print(f"{request.method} : {rjson}")

        userId = Ticket.split('-')[0] if Ticket else None
        print(f"userid: {UserId}")

        if userId is None or len(userId) != 16:
            print("fuh, no good userid")
            return jsonify({
                'resultCode': 2,
                'message': 'FUH',
                'userId': None,
                'nickname': None
            })

        if Platform != 'Quest':
            return jsonify({'Error': 'Bad request', 'Message': 'bro Invalid platform!'}),403

        if Nonce is None:
            return jsonify({'Error': 'Bad request', 'Message': 'HAHA, YOU ARE NOT AUTHENTICATED!'}),304

        req = requests.post(
            url=f"https://{settings.title}.playfabapi.com/Server/GetUserAccountInfo",
            json={"PlayFabId": userId},
            headers={
                "content-type": "application/json",
                "X-SecretKey": secretkey
            })

        print(f"Request to PlayFab returned status code: {req.status_code}")

        if req.status_code == 200:
            nickname = req.json().get("UserInfo",
                                      {}).get("UserAccountInfo",
                                              {}).get("Username")
            if not nickname:
                nickname = None

            print(
                f"user authed {userId.lower()} Nickname: {nickname}"
            )

            return jsonify({
                'resultCode': 1,
                'message':
                f'Authed {userId.lower()} Title {settings.TitleId.lower()}',
                'userId': f'{userId.upper()}',
                'nickname': nickname
            })
        else:
            print("Failed!")
            return jsonify({
                'resultCode': 0,
                'message': "Something is wrong",
                'userId': None,
                'nickname': None
            })

    elif request.method.upper() == "POST":
        rjson = request.get_json()
        print(f"{request.method} : {rjson}")

        ticket = rjson.get("Ticket")
        userId = ticket.split('-')[0] if ticket else None
        print(f"UserId: {userId}")

        if userId is None or len(userId) != 16:
            print("fuh, no good userid")
            return jsonify({
                'resultCode': 2,
                'message': 'FUH',
                'userId': None,
                'nickname': None
            })

        req = requests.post(
             url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
             json={"PlayFabId": userId},
             headers={
                 "content-type": "application/json",
                 "X-SecretKey": settings.SecretKey
             })

        print(f"Authenticated user {userId.lower()}")
        print(f"Request to PlayFab returned status code: {req.status_code}")

        if req.status_code == 200:
             nickname = req.json().get("UserInfo",
                                       {}).get("UserAccountInfo",
                                               {}).get("Username")
             if not nickname:
                 nickname = None
             return jsonify({
                 'resultCode': 1,
                 'message':
                 f'Authenticated user {userId.lower()} title {settings.TitleId.lower()}',
                 'userId': f'{userId.upper()}',
                 'nickname': nickname
             })
        else:
             print("Failed to get user account info from PlayFab")
             successJson = {
                 'resultCode': 0,
                 'message': "Something went wrong",
                 'userId': None,
                 'nickname': None
             }
             authPostData = {}
             for key, value in authPostData.items():
                 successJson[key] = value
             print(f"Returning successJson: {successJson}")
             return jsonify(successJson)
    else:
         print(f"Invalid method: {request.method.upper()}")
         return jsonify({
             "Message":
             "use post or get method instead of " + request.method.upper()
         })

# IF YOU HAVE THIS BACKEND, YOUR GAME IS GONNA GET MODDED, SOONER OR LATER.
# made on 9/14/2025
if __name__ == "__main__":
    app.run("0.0.0.0", 8080) # Made by ires. Gave to l1rson!
