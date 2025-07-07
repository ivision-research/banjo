#!/usr/bin/env python3
import pathlib

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
        Architecture["Smali"].frame = pathlib.Path(file.getFilename()).resolve().as_posix()
        return True

    def OnViewChange(self, context, frame, type):
        if frame:
            Architecture["Smali"].frame = pathlib.Path(context.getCurrentView().getData().file.filename).resolve().as_posix()


notif = UINotification()
