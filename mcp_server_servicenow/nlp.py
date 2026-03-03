"""
Natural Language Processing for ServiceNow MCP Server

This module provides natural language processing capabilities for the ServiceNow MCP server.
"""

import re
from typing import Dict, Any, Tuple, List, Optional

class NLPProcessor:
    """Natural Language Processing for ServiceNow queries and commands"""
    
    @staticmethod
    def parse_search_query(query: str) -> Dict[str, Any]:
        """
        Parse a natural language search query
        
        Examples:
        - "find all incidents about SAP"
        - "search for incidents related to email"
        - "show me all incidents with high priority"
        
        Returns:
            Dict with table, query, and other parameters
        """
        # Default to incident table
        table = "incident"
        
        # Extract table if specified
        table_match = re.search(r'(incidents?|problems?|changes?|tasks?|users?|groups?)', query, re.IGNORECASE)
        if table_match:
            table_type = table_match.group(1).lower()
            if table_type.startswith('incident'):
                table = "incident"
            elif table_type.startswith('problem'):
                table = "problem"
            elif table_type.startswith('change'):
                table = "change_request"
            elif table_type.startswith('task'):
                table = "task"
            elif table_type.startswith('user'):
                table = "sys_user"
            elif table_type.startswith('group'):
                table = "sys_user_group"
        
        # Extract search terms
        about_match = re.search(r'(?:about|related to|regarding|concerning|with|containing)\s+([^\.]+)', query, re.IGNORECASE)
        search_term = ""
        if about_match:
            search_term = about_match.group(1).strip()
        else:
            # Try to find any terms after common search phrases
            term_match = re.search(r'(?:find|search for|show|get|list|display)\s+(?:all|any|)(?:\s+\w+)?\s+(?:\w+\s+)?(.+)', query, re.IGNORECASE)
            if term_match:
                search_term = term_match.group(1).strip()
        
        # Extract priority if mentioned
        priority = None
        if re.search(r'\b(high|critical)\s+priority\b', query, re.IGNORECASE):
            priority = "1"
        elif re.search(r'\b(medium)\s+priority\b', query, re.IGNORECASE):
            priority = "2"
        elif re.search(r'\b(low)\s+priority\b', query, re.IGNORECASE):
            priority = "3"
        
        # Extract state if mentioned
        state = None
        if re.search(r'\b(new|open)\b', query, re.IGNORECASE):
            state = "1"
        elif re.search(r'\b(in progress|working)\b', query, re.IGNORECASE):
            state = "2"
        elif re.search(r'\b(closed|resolved)\b', query, re.IGNORECASE):
            state = "7"
        
        # Build the query string
        query_parts = []
        if search_term:
            query_parts.append(f"123TEXTQUERY321={search_term}")
        if priority:
            query_parts.append(f"priority={priority}")
        if state:
            query_parts.append(f"state={state}")
        
        query_string = "^".join(query_parts) if query_parts else ""
        
        return {
            "table": table,
            "query": query_string,
            "limit": 10
        }
    
    @staticmethod
    def parse_update_command(command: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parse a natural language update command
        
        Examples:
        - "Update incident INC0010001 saying I'm working on it"
        - "Set incident INC0010002 to in progress"
        - "Close incident INC0010003 with resolution: fixed the issue"
        
        Returns:
            Tuple of (record_number, updates_dict)
        """
        # Extract record number
        number_match = re.search(r'(INC\d+|PRB\d+|CHG\d+|TASK\d+)', command, re.IGNORECASE)
        if not number_match:
            raise ValueError("No record number found in command")
        
        record_number = number_match.group(1).upper()
        
        # Initialize updates dictionary
        updates = {}
        
        # Check for state changes
        if re.search(r'\b(working on|in progress|assign)\b', command, re.IGNORECASE):
            updates["state"] = 2  # In Progress
        elif re.search(r'\b(resolve|resolved|fix|fixed)\b', command, re.IGNORECASE):
            updates["state"] = 6  # Resolved
        elif re.search(r'\b(close|closed)\b', command, re.IGNORECASE):
            updates["state"] = 7  # Closed
        
        # Extract comments or work notes
        comment_match = re.search(r'(?:saying|comment|note|with comment|with note)(?:s|)\s*:?\s*(.+?)(?:$|\.(?:\s|$))', command, re.IGNORECASE)
        if comment_match:
            comment_text = comment_match.group(1).strip()
            # Determine if this should be a comment or work note
            if re.search(r'\b(work note|internal|private)\b', command, re.IGNORECASE):
                updates["work_notes"] = comment_text
            else:
                updates["comments"] = comment_text
        
        # Extract close notes and codes if closing/resolving
        if "state" in updates and updates["state"] in [6, 7]:
            close_code_match = re.search(
                r'(?:resolution\s*code|close\s*code|close_code|resolution_code)\s*:?\s*(.+?)(?=\s+and\s+(?:resolution|close)\s*notes?|\s*$|\.|;)',
                command,
                re.IGNORECASE
            )
            if close_code_match:
                updates["close_code"] = close_code_match.group(1).strip()

            close_notes_match = re.search(
                r'(?:resolution\s*notes?|close\s*notes?|close_notes|resolution_notes|close\s*note|resolution\s*note)\s*:?\s*(.+?)(?:$|\.(?:\s|$))',
                command,
                re.IGNORECASE
            )
            if close_notes_match:
                updates["close_notes"] = close_notes_match.group(1).strip()

            if "close_notes" in updates and "close_code" not in updates:
                updates["close_code"] = "Solved (Permanently)"
# ...existing code...
        
        return record_number, updates
    
    @staticmethod
    def parse_script_update(command: str) -> Tuple[str, str, str]:
        """
        Parse a command to update a ServiceNow script file
        
        Examples:
        - "update @my_script.js, it's a script include"
        - "update @business_rule.js, it's a business rule"
        
        Returns:
            Tuple of (filename, script_type, script_content)
        """
        # Extract filename
        filename_match = re.search(r'@([^\s,]+)', command)
        if not filename_match:
            raise ValueError("No filename found in command")
        
        filename = filename_match.group(1)
        
        # Extract script type
        script_types = {
            "script include": "sys_script_include",
            "business rule": "sys_script",
            "client script": "sys_script_client",
            "ui script": "sys_ui_script",
            "ui action": "sys_ui_action",
            "ui page": "sys_ui_page",
            "ui macro": "sys_ui_macro",
            "scheduled job": "sysauto_script",
            "fix script": "sys_script_fix"
        }
        
        script_type = None
        for type_name, table_name in script_types.items():
            if re.search(rf"\b{type_name}\b", command, re.IGNORECASE):
                script_type = table_name
                break
        
        if not script_type:
            # Default to script include if not specified
            script_type = "sys_script_include"
        
        # The script content will be provided separately
        return filename, script_type, ""
