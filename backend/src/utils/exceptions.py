class ProjectDoesNotExistException(Exception):
    def __init__(self, message, project_id: str):
        super().__init__(message)
        self.project_id = project_id
        
class TargetDoesNotExistException(ValueError):
    def __init__(self, message, target_id: str):
        super().__init__(message)
        self.target_id = target_id
        
class DurationNotDefinedInTarget(Exception):
    def __init__(self, message):
        super().__init__(message)

class AgentAlreadyRunningException(Exception):
    def __init__(self, message, target_id: str):
        super().__init__(message)
        self.target_id = target_id

class ModelNotSelectedException(Exception):
    def __init__(self, message):
        super().__init__(message)

class ModelNotInstalledException(Exception):
    def __init__(self, message, model_name: str):
        super().__init__(message)
        self.model_name = model_name

class SessionDoesNotExistException(Exception):
    def __init__(self, message, session_id: str):
        super().__init__(message)
        self.session_id = session_id

class SessionIsRunningException(Exception):
    def __init__(self, message, session_id: str):
        super().__init__(message)
        self.session_id = session_id

class InvalidProjectIdException(ValueError):
    def __init__(self, message, project_id: str):
        super().__init__(message)
        self.project_id = project_id

class InvalidTargetDataException(ValueError):
    def __init__(self, message):
        super().__init__(message)

class ModelAlreadyDownloadingException(ValueError):
    def __init__(self, message, model_name: str):
        super().__init__(message)
        self.model_name = model_name

class ModelAlreadyDownloadedException(ValueError):
    def __init__(self, message, model_name: str):
        super().__init__(message)
        self.model_name = model_name