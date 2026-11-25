# Records the terminal GIF for the README.
#
#   vhs demo/demo.tape          (run from the repository root)
#
# VHS: https://github.com/charmbracelet/vhs  (it also needs ttyd and ffmpeg)
# The recording shows the setup questions, then a quick check of the fake
# demo app, ending on the summary. It needs bash, git and node, and the
# network for the audit step.

Output demo/demo.gif

Require bash
Require git
Require node

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 18
Set TypingSpeed 45ms

# Build the fake app off-screen.
Hide
Type "rm -rf /tmp/demo-shop && bash demo/make-demo-app.sh /tmp/demo-shop >/dev/null && clear"
Enter
Sleep 2s
Show

Type "./node-security-check.sh /tmp/demo-shop"
Sleep 600ms
Enter
Sleep 2s

# What do you want to check?  2 = packages and code
Type "2"
Sleep 500ms
Enter
Sleep 1500ms

# How thorough?  1 = quick
Type "1"
Sleep 500ms
Enter
Sleep 1500ms

# Which package manager?  Enter accepts the suggestion (npm)
Enter
Sleep 1500ms

# Save these answers?  n
Type "n"
Sleep 500ms
Enter
Sleep 1200ms

# Start the check?  Enter = yes
Enter

# The findings scroll past; the summary stays on screen at the end.
Sleep 14s
