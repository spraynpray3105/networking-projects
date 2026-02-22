#   KnockOnWood - Checks for system hardening and provides a detailed report of measures.
# 
#   This tool was created for learning purposes only and is not intended to be a feature
#   rich tool. It teaches concepts relating multiple layers of the OSI model and cyber 
#   security concepts.
#
#   | GNU v3.0 GENERAL PUBLIC LICENSE | ELIJAH MARTIN | 2026 |

# IMPORTS
import os
import winreg
import subprocess

POLICY_PATH = ''
server_name = None


class checksys:
    # Initialize
    def __init__(self):
        pass
    
    # Run the system check
    def run(self):
        pass

    # Generate the hardening report
    def report(self, data):
        pass
    
    # Loads user related policies from AD
    def userpolicies(self, policy, server=None):
        pass

    # Loads AD Policy, defaults server to None if not provided.
    def getpolicy(self, server=None):
        try:
            pass
        except:
            pass


if __name__ == '__main__':
    checksys().run()
