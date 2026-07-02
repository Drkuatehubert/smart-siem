class AppException(Exception):
    pass

class UserAlreadyExistsError(AppException): pass
class InvalidCredentialsError(AppException): pass
class AccountInactiveError(AppException): pass
class AccountLockedError(AppException): pass
class InvalidTokenError(AppException): pass
class UserNotFoundError(AppException): pass
class SamePasswordError(AppException): pass
class InfoUserAlreadyExistsError(AppException): pass
class InfoUserNotFoundError(AppException) : pass