

The protocol used is not classical IoT data sync, but rather a protocol
initially used for communicating with a display device, where part of the
business logic is done on the device.

For example, there might be a list of available states of some setting, but it
is not editable. Editing happens in a "random" screen that is not easily
connected to the actual multivalue state variable whose state changes are
automatically pushed to us.

The editing screen is then simply a set of UI buttons, and when one presses
them it is on-device logic that does the state change.



When object has a type 1, this means that the button is meant to be
rendered. That button then takes us to a screen in this way:
  - new screenid is "detail" and if there is an "objID", this is another
    qualifier as screens are defined by screenid+objID
