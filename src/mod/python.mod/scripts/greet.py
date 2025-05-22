# Enhanced greet.py - Demonstrates improved rehash handling and bind management

# Load bind from eggdrop, not eggdrop.tcl. Loading it from eggdrop.tcl would cause
# the bind to call a Tcl proc, not the python function.
from eggdrop import bind, register_rehash_handler

# Load any Tcl commands you want to use from the eggdrop.tcl module.
from eggdrop.tcl import putmsg, putlog

# Global list to track our binds
GREET_BINDS = []

def joinGreetUser(nick, host, handle, channel, **kwargs):
    """Greet regular users joining the channel"""
    try:
        putmsg(channel, f"Hello {nick}, welcome to {channel}!")
    except Exception as e:
        putlog(f"Error in joinGreetUser: {e}")

def joinGreetOp(nick, host, handle, channel, **kwargs):
    """Special greeting for operators"""
    try:
        putmsg(channel, f"{nick} is an operator on this channel!")
    except Exception as e:
        putlog(f"Error in joinGreetOp: {e}")

def cleanup_binds():
    """Clean up existing binds before creating new ones"""
    global GREET_BINDS
    
    putlog("Cleaning up greet.py binds...")
    for greetbind in GREET_BINDS:
        try:
            greetbind.unbind()
        except Exception as e:
            putlog(f"Error unbinding: {e}")
    
    GREET_BINDS.clear()
    putlog("Greet.py binds cleaned up successfully")

def setup_binds():
    """Set up all binds for this script"""
    global GREET_BINDS
    
    try:
        # Create the binds
        GREET_BINDS.append(bind("join", "*", "*", joinGreetUser))
        GREET_BINDS.append(bind("join", "o", "*", joinGreetOp))
        
        putlog(f"Greet.py: Created {len(GREET_BINDS)} binds")
        
    except Exception as e:
        putlog(f"Error setting up greet.py binds: {e}")

def on_rehash():
    """Handler called when eggdrop is rehashed"""
    putlog("Greet.py: Handling rehash event")
    cleanup_binds()
    setup_binds()

# Main script execution

# Clean up any existing binds from previous loads
if 'GREET_BINDS' in globals() and GREET_BINDS:
    cleanup_binds()

# Set up new binds
setup_binds()

# Register our rehash handler
try:
    register_rehash_handler(on_rehash)
    putlog("Greet.py: Registered rehash handler")
except Exception as e:
    putlog(f"Greet.py: Could not register rehash handler: {e}")

putlog("Greet.py loaded successfully")
