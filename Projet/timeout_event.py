from ryu.base import app_manager
from ryu.controller import event
from ryu.lib import hub


# A user defined event class
#Copy to /usr/local/lib/python2.7/dist-packages/ryu/app/timeout_event.py
class SendTimeout(event.EventBase):
    def __init__(self, msg):
        super(SendTimeout, self).__init__()
        self.msg = msg


class EventSenderTimeOut(app_manager.RyuApp):
    # Register user defined events which this RyuApp would generate
    _EVENTS = [SendTimeout]

    def _periodic_event_loop(self):
        while True:
            hub.sleep(5)
            ev = SendTimeout('SendTimeout')
            self.logger.info('*** Send event: event.msg = %s', ev.msg)
            self.send_event_to_observers(ev)

    def start(self):
        super(EventSenderTimeOut, self).start()
        # Start user defined event loop
        self.threads.append(hub.spawn(self._periodic_event_loop))
        print("Apres thread")
