/**
 *   Google Calendar Service Manager
 *
 *   Author: scott, modified by qedi
 *   Date: 2013-08-07
 *
 *  Last Sync from Ecobee: 2015-06-01
 */


definition(
    name: "Google Calendar Trigger",
    namespace: "qedi-r",
    author: "Ryan Bianchi",
    description: "Integrates SmartThings with Google Calendar to trigger events based on calendar items.",
    category: "Mode Magic",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
    iconX3Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png",
//    oauth: [displayName: "SmartThings Google Calendar Integration", displayLink: "http://infornoraphy.ca/"]
) {
   appSetting "clientId"
   appSetting "clientSecret"
   appSetting "serverUrl"
}

preferences {
   page(name: "auth", title: "Google Calendar", nextPage:"tokenRequest", content:"authPage", uninstall: true)
   page(name: "tokenRequest", title: "Google Calendar", nextPage:"calendarList", content:"tokenRequest", uninstall: true)
   page(name: "calendarList", title: "Google Calendar", content:"calendarList", install:true)
}

mappings {
   path("/auth") {
      action: [
        GET: "auth"
      ]
   }
   path("/swapToken") {
      action: [
         GET: "swapToken"
      ]
   }
}

def auth() {
   log.debug "auth()"
   redirect location: oauthInitUrl()
}

def authPage()
{
   log.debug "authPage()"

   if(!atomicState.accessToken)
   {
      log.debug "about to create access token"
      createAccessToken()
      atomicState.accessToken = state.accessToken
   }


   def description = "Required"
   def uninstallAllowed = false
   def oauthTokenProvided = false

   if(atomicState.authToken)
   {
      // TODO: Check if it's valid
      if(true)
      {
         description = "You are connected."
         uninstallAllowed = true
         oauthTokenProvided = true
      }
      else
      {
         description = "Required" // Worth differentiating here vs. not having atomicState.authToken?
         oauthTokenProvided = false
      }
   } else {
      log.warn "atomicState.authToken is false"
   }

   def redirectUrl = buildRedirectUrl("auth")

   log.debug "RedirectUrl = ${redirectUrl}"

   // get rid of next button until the user is actually auth'd

   if (!oauthTokenProvided) {
      log.debug "no oauthTokenProvided"

      return dynamicPage(name: "auth", title: "Login", nextPage:null, uninstall:uninstallAllowed) {
         section(){
            paragraph "Tap below to log in to Google and authorize SmartThings access. Copy and paste the access token into the field below."
            href url:redirectUrl, style:"embedded", required:false, title:"get google oauth token", description:description
         }
         section() {
            input(
            name: "authorization_code", 
            type: "string", 
            title: "access token", 
            required: true,
         )}
         section(){
            paragraph "skip"
            href url:buildRedirectUrl("calendarList"), style:"embedded", required:false, title:"skip", description:description
         }
      }
   } else {
      log.debug "already logged in"

      return dynamicPage(name: "auth", title: "Log In", nextPage:"calendarList", uninstall:uninstallAllowed) {
         section(){
            paragraph "Tap Next to continue to set up your calendar"
            href url:redirectUrl, style:"embedded", state:"complete", title:"google calendar", description:description
         }
      }

   }

}

def calendarList()
{
   log.debug "calendarList()"

   def stats = getCalendarList()

   log.debug "device list: $stats"

   def p = dynamicPage(name: "calendarList", title: "Select Your Calendar", uninstall: true) {
      section(""){
         paragraph "Tap below to see the list of calendars in your Google account and select the one you want to connect to SmartThings."
         input(name: "thermostats", title:"", type: "enum", required:true, multiple:false, description: "Tap to choose", metadata:[values:stats])
      }
   }
   log.debug "list p: $p"
   return p
}

def getCalendarList()
{
   log.debug "getting calendar list"

   def calendarListParams = [
      uri: "https://www.googleapis.com",
      path: "/calendar/v3/users/me/calendarList",
      headers: ["Content-Type": "text/json", "Authorization": "Bearer ${atomicState.authToken}"],
      query: [format: 'json', body: requestBody]
   ]

   log.debug "_______AUTH______ ${atomicState.authToken}"
   log.debug "calendar list params: $calendarListParams"

   def stats = [:]
   try {
      httpGet(calendarListParams) { resp ->

         resp.data.items.each { stat ->
            stats[stat.etag] = getCalendarDisplayName(stat.etag)
         }
      }
   } catch (e) {
       log.debug "http error getting calendarList"
       log.error e.getResponse().getData()
   }

   return stats
}

def installed() {
   log.debug "Installed with settings: ${settings}"
   initialize()
}

def updated() {
   log.debug "Updated with settings: ${settings}"
   unsubscribe()
   initialize()
}

def initialize() {
   // TODO: subscribe to attributes, devices, locations, etc.
   log.debug "initialize"
   def devices = calendars.collect { dni ->

      def d = getChildDevice(dni)

      if(!d)
      {
         d = addChildDevice(getChildNamespace(), getChildName(), dni)
         log.debug "created ${d.displayName} with id $dni"
      }
      else
      {
         log.debug "found ${d.displayName} with id $dni already exists"
      }

      return d
   }

   log.debug "created ${devices.size()} calendars"

   def delete
   // Delete any that are no longer in settings
   if(!calendars)
   {
      log.debug "delete calendars"
      delete = getAllChildDevices()
   }
   else
   {
      delete = getChildDevices().findAll { !calendars.contains(it.deviceNetworkId) }
   }

   log.debug "deleting ${delete.size()} calendars"
   delete.each { deleteChildDevice(it.deviceNetworkId) }

   atomicState.calendarData = [:]

   pollHandler()

   // schedule ("0 0/15 * 1/1 * ? *", pollHandler)
}


def oauthInitUrl()
{
   log.debug "oauthInitUrl"
   // def oauth_url = "https://api.ecobee.com/authorize?response_type=code&client_id=qqwy6qo0c2lhTZGytelkQ5o8vlHgRsrO&redirect_uri=http://localhost/&scope=smartRead,smartWrite&state=abc123"
   def stcid = getAppClientId();

   atomicState.oauthInitState = UUID.randomUUID().toString()

   def oauthParams = [
      response_type: "code",
      scope: "https://www.googleapis.com/auth/calendar.readonly",
      client_id: stcid,
      state: atomicState.oauthInitState,
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob"
   ]

   return "https://accounts.google.com/o/oauth2/auth?" + toQueryString(oauthParams)
}

def buildRedirectUrl(action = "swapToken")
{
   log.debug "buildRedirectUrl"
   // return serverUrl + "/api/smartapps/installations/${app.id}/token/${atomicState.accessToken}"
   return "https://graph.api.smartthings.com/api/token/${atomicState.accessToken}/smartapps/installations/${app.id}/${action}"
}

def tokenRequest()
{
   log.debug "token request: $authorization_code"
   debugEvent ("token request")

   def postParams = [
       uri: "https://www.googleapis.com",
         path: "/oauth2/v3/token",
       requestContentType: "application/x-www-form-urlencoded; charset=utf-8",
       body: [
            code: authorization_code,
            client_secret: getAppClientSecret(),
            client_id: getAppClientId(),
            grant_type: "authorization_code",
            redirect_uri: "urn:ietf:wg:oauth:2.0:oob"
         ]
   ]

   log.debug postParams

   def jsonMap
    try {
        httpPost(postParams) { resp ->
             log.debug "resp"
             log.debug resp.data
            jsonMap = resp.data
        }
    } catch (e) {
        log.error "something went wrong: $e"
        log.error e.getResponse().getData()
        return
    }

   atomicState.refreshToken = jsonMap.refresh_token
   atomicState.authToken = jsonMap.access_token
     
   redirect location: calendarList()
}


def toQueryString(Map m)
{
   return m.collect { k, v -> "${k}=${URLEncoder.encode(v.toString())}" }.sort().join("&")
}

private refreshAuthToken() {
   log.debug "refreshing auth token"
   debugEvent("refreshing OAUTH token")

   if(!atomicState.refreshToken) {
      log.warn "Can not refresh OAuth token since there is no refreshToken stored"
   } else {
      def stcid = getAppClientId()

      def refreshParams = [
            method: 'POST',
            uri   : "https://api.ecobee.com",
            path  : "/token",
            query : [grant_type: 'refresh_token', code: "${atomicState.refreshToken}", client_id: stcid],

            //data?.refreshToken
      ]

      log.debug refreshParams

      //changed to httpPost
      try {
         def jsonMap
         httpPost(refreshParams) { resp ->

            if(resp.status == 200) {
               log.debug "Token refreshed...calling saved RestAction now!"

               debugEvent("Token refreshed ... calling saved RestAction now!")

               log.debug resp

               jsonMap = resp.data

               if(resp.data) {

                  log.debug resp.data
                  debugEvent("Response = ${resp.data}")

                  atomicState.refreshToken = resp?.data?.refresh_token
                  atomicState.authToken = resp?.data?.access_token

                  debugEvent("Refresh Token = ${atomicState.refreshToken}")
                  debugEvent("OAUTH Token = ${atomicState.authToken}")

                  if(atomicState.action && atomicState.action != "") {
                     log.debug "Executing next action: ${atomicState.action}"

                     "{atomicState.action}"()

                     //remove saved action
                     atomicState.action = ""
                  }

               }
               atomicState.action = ""
            } else {
               log.debug "refresh failed ${resp.status} : ${resp.status.code}"
            }
         }

         // atomicState.refreshToken = jsonMap.refresh_token
         // atomicState.authToken = jsonMap.access_token
      }
      catch(Exception e) {
         log.debug "caught exception refreshing auth token: " + e
      }
   }
}

def resumeProgram(child)
{

   def thermostatIdsString = getChildDeviceIdsString()
   log.debug "resumeProgram children: $thermostatIdsString"

   def jsonRequestBody = '{"selection":{"selectionType":"thermostats","selectionMatch":"' + thermostatIdsString + '","includeRuntime":true},"functions": [{"type": "resumeProgram"}]}'
   //, { "type": "sendMessage", "params": { "text": "Setpoint Updated" } }
   sendJson(jsonRequestBody)
}

def setHold(child, heating, cooling)
{

   int h = heating * 10
   int c = cooling * 10

   log.debug "setpoints____________ - h: $heating - $h, c: $cooling - $c"
   def thermostatIdsString = getChildDeviceIdsString()
   log.debug "setCoolingSetpoint children: $thermostatIdsString"



   def jsonRequestBody = '{"selection":{"selectionType":"thermostats","selectionMatch":"' + thermostatIdsString + '","includeRuntime":true},"functions": [{ "type": "setHold", "params": { "coolHoldTemp": '+c+',"heatHoldTemp": '+h+', "holdType": "indefinite" } } ]}'

//   def jsonRequestBody = '{"selection":{"selectionType":"thermostats","selectionMatch":"' + thermostatIdsString + '","includeRuntime":true},"functions": [{"type": "resumeProgram"}, { "type": "setHold", "params": { "coolHoldTemp": '+c+',"heatHoldTemp": '+h+', "holdType": "indefinite" } } ]}'

   sendJson(jsonRequestBody)
}

def setMode(child, mode)
{
   log.debug "requested mode = ${mode}"
   def thermostatIdsString = getChildDeviceIdsString()
   log.debug "setCoolingSetpoint children: $thermostatIdsString"


   def jsonRequestBody = '{"selection":{"selectionType":"thermostats","selectionMatch":"' + thermostatIdsString + '","includeRuntime":true},"thermostat": {"settings":{"hvacMode":"'+"${mode}"+'"}}}'

   log.debug "Mode Request Body = ${jsonRequestBody}"
   debugEvent ("Mode Request Body = ${jsonRequestBody}")

   def result = sendJson(jsonRequestBody)

   if (result) {
      def tData = atomicState.thermostats[child.device.deviceNetworkId]
      tData.data.thermostatMode = mode
   }

   return(result)
}

def changeSetpoint (child, amount)
{
   def tData = atomicState.thermostats[child.device.deviceNetworkId]

   log.debug "In changeSetpoint."
   debugEvent ("In changeSetpoint.")

   if (tData) {

      def thermostat = tData.data

      log.debug "Thermostat=${thermostat}"
      debugEvent ("Thermostat=${thermostat}")

      if (thermostat.thermostatMode == "heat") {
         thermostat.heatingSetpoint = thermostat.heatingSetpoint + amount
         child.setHeatingSetpoint (thermostat.heatingSetpoint)

         log.debug "New Heating Setpoint = ${thermostat.heatingSetpoint}"
         debugEvent ("New Heating Setpoint = ${thermostat.heatingSetpoint}")

      }
      else if (thermostat.thermostatMode == "cool") {
         thermostat.coolingSetpoint = thermostat.coolingSetpoint + amount
         child.setCoolingSetpoint (thermostat.coolingSetpoint)

         log.debug "New Cooling Setpoint = ${thermostat.coolingSetpoint}"
         debugEvent ("New Cooling Setpoint = ${thermostat.coolingSetpoint}")
      }
   }
}


def sendJson(String jsonBody)
{

   //log.debug "_____AUTH_____ ${atomicState.authToken}"

   def cmdParams = [
      uri: "https://api.ecobee.com",

      path: "/1/thermostat",
      headers: ["Content-Type": "application/json", "Authorization": "Bearer ${atomicState.authToken}"],
      body: jsonBody
   ]

   def returnStatus = -1

   try{
      httpPost(cmdParams) { resp ->

         if(resp.status == 200) {

            log.debug "updated ${resp.data}"
            debugEvent("updated ${resp.data}")
            returnStatus = resp.data.status.code
            if (resp.data.status.code == 0)
               log.debug "Successful call to ecobee API."
            else {
               log.debug "Error return code = ${resp.data.status.code}"
               debugEvent("Error return code = ${resp.data.status.code}")
            }
         }
         else
         {
            log.error "sent Json & got http status ${resp.status} - ${resp.status.code}"
            debugEvent ("sent Json & got http status ${resp.status} - ${resp.status.code}")

            //refresh the auth token
            if (resp.status == 500 && resp.status.code == 14)
            {
               //log.debug "Storing the failed action to try later"
               log.debug "Refreshing your auth_token!"
               debugEvent ("Refreshing OAUTH Token")
               refreshAuthToken()
               return false
            }
            else
            {
               debugEvent ("Authentication error, invalid authentication method, lack of credentials, etc.")
               log.error "Authentication error, invalid authentication method, lack of credentials, etc."
               return false
            }
         }
      }
   }
   catch(Exception e)
   {
      log.debug "Exception Sending Json: " + e
      debugEvent ("Exception Sending JSON: " + e)
      return false
   }

   if (returnStatus == 0)
      return true
   else
      return false
}


def getChildNamespace() { "smartthings" }
def getChildName() { "Ecobee Thermostat" }

def getServerUrl() { return appSettings.serverUrl }
def getAppClientId() { appSettings.clientId }
def getAppClientSecret() { appSettings.clientSecret }

def debugEvent(message, displayEvent = false) {

   def results = [
      name: "appdebug",
      descriptionText: message,
      displayed: displayEvent
   ]
   log.debug "Generating AppDebug Event: ${results}"
   sendEvent (results)

}


