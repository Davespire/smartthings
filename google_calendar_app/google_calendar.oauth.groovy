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
) {
   appSetting "clientId"
   appSetting "clientSecret"
   appSetting "serverUrl"
}

preferences {
   page(name: "auth", title: "Google Calendar", nextPage:"calendarList", content:"authPage", uninstall: true)
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
   path("/calendarList") {
      action: [
         GET: "calendarList"
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
   def oauthTokenProvided = checkAuthToken()

   def redirectUrl = buildRedirectUrl("auth")

   log.debug "RedirectUrl = ${redirectUrl}"

   // get rid of next button until the user is actually auth'd

   if (!oauthTokenProvided) {
      log.debug "no oauthTokenProvided"

      return dynamicPage(name: "auth", title: "Login", nextPage:"calendarList", uninstall:uninstallAllowed) {
         section(){
            paragraph "Tap below to log in to Google and authorize SmartThings access. Copy and paste the access token into the field below."
            href url:redirectUrl, style:"embedded", required:false, title:"get google oauth token", description:"Required"
         }
         section() {
            input(
            name: "authorization_code", 
            type: "string", 
            title: "access token", 
            required: true,
         )}
      }
   } else {
      log.debug "already logged in"

      return dynamicPage(name: "auth", title: "Log In", nextPage:"calendarList", uninstall:uninstallAllowed) {
         section(){
            paragraph "Tap Next to continue to set up your calendar"
            href(
               name: "toCalendarList", 
               page: "calendarList", 
               style:"embedded", 
               state:"complete", 
               title:"google calendar", 
               description:"You are connected"
            )
         }
      }

   }

}

def calendarList()
{
   log.debug "calendarList()"
   if (!checkAuthToken()) {
      tokenRequest()
   }

   def stats = getCalendarList()

   log.debug "device list: $stats"

   def p = dynamicPage(name: "calendarList", title: "Select Your Calendar", uninstall: true) {
      section(){
         paragraph "Tap below to see the list of calendars in your Google account and select the one you want to connect to SmartThings."
         input(name: "watchCalendars", title:"", type: "enum", required:true, multiple:true, description: "Tap to choose", metadata:[values:stats])
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
            stats[stat.etag] = stat.summary
         }
      }
   } catch (e) {
       log.debug "http error getting ${path}"
       log.debug e
       if(!atomicState.action || atomicState.action == "") {
          log.debug "trying again"
          atomicState.action = "getCalendarList"
          return refreshAuthToken()
       } else {
          log.debug "unresolvable"
          log.error e.getResponse().getData()
       }
   }

   return stats
}

def getNextEvents()
{
   log.debug "getting event list"
   def pathParams = [
      maxResults: 5,
      orderBy: "startTime",
      singleEvents: "true",
      timeMin: getCurrentTime()
   ]
   def pathParamsString = toQueryString(pathParams)

   def eventListParams = [
      uri: "https://www.googleapis.com",
      path: "/calendar/v3/users/calendars/${id}/events?${pathParamsString}",
      headers: ["Content-Type": "text/json", "Authorization": "Bearer ${atomicState.authToken}"],
      query: [format: 'json', body: none]
   ]

   log.debug "_______AUTH______ ${atomicState.authToken}"
   log.debug "event list params: $eventListParams"

   def stats = [:]
   try {
      httpGet(eventListParams) { resp ->
         ev = resp.data.items.first 
      }
   } catch (e) {
       log.debug "http error getting ${path}"
       log.debug e
       if(!atomicState.action || atomicState.action == "") {
          log.debug "trying again"
          atomicState.action = "getNextEvents"
          return refreshAuthToken()
       } else {
          log.debug "unresolvable"
          log.error e.getResponse().getData()
       }
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
   log.debug "initialize"
   log.debug watchCalendars

   def calendarsToDelete
   calendarsToDelete = getAllChildDevices()
   calendarsToDelete.each { deleteChildDevice(it.deviceNetworkId) }

   def d = getChildDevice(watchCalendars)
   watchCalendars.each { wc -> 
      log.debug d

      if(!d)
      {
         log.debug "creating device"
         log.debug getChildNamespace()
         log.debug getChildName()
         d = addChildDevice(getChildName(), wc)
         log.debug "created ${d.displayName} with id $wc"
      }
      else
      {
         log.debug "found ${d.displayName} with id $dni already exists"
      }

      log.debug "created calendar to watch"
   }

   runEvery30Minutes(pollHandler)

   // schedule ("0 0/15 * 1/1 * ? *", pollHandler)
}

def pollHandler()
{
   log.debug("pollhandler")
   calendarsToCheck = getAllChildDevices()
   calendarsToCheck.each { 
      ev = getNextEvents(it)
      log.debug(ev)
      ev.each { e -> 
         log.debug(e)
      }
   }
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
   return "https://graph.api.smartthings.com/api/token/${atomicState.accessToken}/smartapps/installations/${app.id}/${action}"
}

def tokenRequest()
{
   if (authorization_code == null) {
      return
   }
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
     
   return
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
            uri   : "https://www.googleapis.com",
            path  : "/oauth2/v3/token",
            body : [
               grant_type: 'refresh_token', 
               code: "${atomicState.refreshToken}", 
               client_secret: getAppClientSecret(),
               client_id: getAppClientId()
            ],
      ]

      log.debug refreshParams

      //changed to httpPost
      try {
         def jsonMap
         httpPost(refreshParams) { resp ->
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

                  return "{atomicState.action}"()

                  //remove saved action
                  atomicState.action = ""
               }
            }
            atomicState.action = ""
         }
      }
      catch(Exception e) {
         log.debug "caught exception refreshing auth token: " + e
         log.error e.getResponse().getData()
      }
   }
}
def checkAuthToken() {
   if(atomicState.authToken && 
      // TODO: Check if it's valid
      true)
   {
      return true;
   } else {
      return false;
   }

}

def toQueryString(Map m)
{
   return m.collect { k, v -> "${k}=${URLEncoder.encode(v.toString())}" }.sort().join("&")
}

def getCurrentTime() {
   //RFC 3339 format
   //2015-06-20T11:39:45.0Z
   d = new Date()
   return String.format("%04d-%02d-%02dT%02d:%02d:%02d.000Z"
      , d.year+1900
      , d.month
      , d.day
      , d.hour
      , d.minute
      , d.second
   )

}

def getChildNamespace() { "qedi-r" }
def getChildName() { "Calendar Event Sensor" }

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


