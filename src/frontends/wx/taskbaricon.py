
import wx

class LoxodoTaskBarIcon(wx.TaskBarIcon):
    def __init__(self, icon, tooltip, frame):
        wx.TaskBarIcon.__init__(self)
        self.SetIcon(icon, tooltip)
        self.frame = frame
        self.Bind(wx.EVT_TASKBAR_LEFT_UP, self.on_click)
        self.Bind(wx.EVT_TASKBAR_RIGHT_UP, self.on_click)

    def on_click(self, e):
        if self.frame.IsIconized() or not self.frame.IsShown():
            self.frame.Show()
            self.frame.Restore()
            self.frame.Raise()
        else:
            self.frame.Hide()
            self.frame.Iconize()

