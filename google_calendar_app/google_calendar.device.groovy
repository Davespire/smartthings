/**
 */
metadata {
	definition (name: "Calendar Event Sensor", namespace: "qedi-r", author: "Ryan Bianchi") {
		capability "Contact Sensor"
		capability "Sensor"
		attribute "nextTrigger", "string"
		attribute "nextEvent", "string"
		attribute "calendarId", "string"
	}

	// UI tile definitions
	tiles {
		standardTile("contact", "device.contact", width: 2, height: 2) {
			state "open", label: '${name}', icon: "st.contact.contact.open", backgroundColor: "#ffa81e"
			state "closed", label: '${name}', icon: "st.contact.contact.closed", backgroundColor: "#79b821"
		}

		main "contact"
		details "contact"
	}
}

def setNextEvent(ntStartTime, ntEndTime, desc) {
    log.debug "set nextTrigger"
	sendEvent(name: "nextTrigger", value: Date3339to8601(ntStartTime));
    log.debug "will close at ${ntEndTime}"
    
    def future = null;
    if (ntEndTime != null) {
    	future = Date3339to8601(ntEndTime);
 	} else {
    	//default to one minute
        def then = new Date(new Date().getTime() + 60 * 1000)
        future = Date3389Format(then)
    }
    
    runOnce(Date3339to8601(ntStartTime), setClosed);
    runOnce(future, setOpen);
}

def setClosed()
{
	sendEvent(name: "contact", value: "closed");
}

def setOpen()
{
	sendEvent(name: "contact", value: "open")
}

def Date3339to8601(String s) {
   s = s.replaceAll(~/([+-][0-9][0-9]):([0-9][0-9])/, "\$1\$2")
   s = s.replaceAll(~/(:[0-9][0-9])([-+Z])/, "\$1.000\$2")
   return s
}

def Date3339Format(Date d) {
   return String.format("%04d-%02d-%02dT%02d:%02d:%02d.000Z"
      , d.year+1900
      , d.month
      , d.day
      , d.hours
      , d.minutes
      , d.seconds
   )
}
