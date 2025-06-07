import os
import clamd
from typing import Dict, Union

class AntiVirusScanner:
    def __init__(self):
        try:
            self.clam = clamd.ClamdNetworkSocket()
            # Test the connection
            self.clam.ping()
        except Exception as e:
            try:
                # Try to connect to local socket if network socket fails
                self.clam = clamd.ClamdUnixSocket()
                self.clam.ping()
            except Exception as e:
                raise Exception("Could not connect to ClamAV daemon. Make sure it's running.") from e

    def scan_file(self, file_path: str) -> Dict[str, Union[bool, str]]:
        """
        Scan a file for viruses using ClamAV
        
        Args:
            file_path (str): Path to the file to scan
            
        Returns:
            dict: Result containing scan status and any threats found
        """
        try:
            if not os.path.exists(file_path):
                return {
                    "success": False,
                    "error": "File not found",
                    "is_infected": False,
                    "threats": []
                }

            scan_result = self.clam.scan(file_path)
            file_scan_result = scan_result.get(file_path)

            if file_scan_result[0] == "OK":
                return {
                    "success": True,
                    "is_infected": False,
                    "threats": []
                }
            else:
                return {
                    "success": True,
                    "is_infected": True,
                    "threats": [file_scan_result[1]]
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "is_infected": False,
                "threats": []
            }

    def get_version(self) -> str:
        """Get ClamAV version"""
        try:
            return self.clam.version()
        except Exception as e:
            return f"Error getting version: {str(e)}" 