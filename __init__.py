#!/usr/bin/env python3

from .architecture import Smali
from .binaryview import Dex

Smali.register()
Dex.register()


from binaryninjaui import UIContextNotification, UIContext  # type: ignore
from binaryninja.architecture import Architecture  # type: ignore


class UINotification(UIContextNotification):
    def __init__(self):
        UIContextNotification.__init__(self)
        UIContext.registerNotification(self)

    def __del__(self):
        UIContext.unregisterNotification(self)

    def OnBeforeOpenFile(self, context, file):
        Architecture["Smali"].frame = file.getFilename().rsplit("/", 1)[-1]
        return True

    def OnViewChange(self, context, frame, type):
        if frame:
            Architecture["Smali"].frame = frame.getShortFileName()


notif = UINotification()
