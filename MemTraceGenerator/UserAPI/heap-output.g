gef config context.enable 0
gef config gef.disable_color True
b *(main + 229)
commands
heap bins
print "==Chunks=="
heap chunks
print "==Chunks Done=="
call fflush(0)
c
end

b *(main + 322)
commands
heap bins
print "==Chunks=="
heap chunks
print "==Chunks Done=="
call fflush(0)
c
end

r trace
quit
