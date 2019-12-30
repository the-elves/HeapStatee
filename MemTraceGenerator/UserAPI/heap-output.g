gef config context.enable 0
b *(main + 228)
commands
heap bins
print "==Chunks=="
heap chunks
print "==Chunks Done=="
call fflush(0)
c
end

b *(main + 319)
commands
heap bins
print "==Chunks=="
heap chunks
print "==Chunks Done=="
call fflush(0)
c
end

r trace

