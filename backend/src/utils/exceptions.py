class ProjectDoesNotExistException(Exception):
    def __init__(self, message, project_id: str):
        super().__init__(message)
        self.project_id = project_id
        
class TargetDoesNotExistException(Exception):
    def __init__(self, message, target_id: str):
        super().__init__(message)
        self.target_id = target_id