from rest_framework.authentication import TokenAuthentication as BaseTokenAuth
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import BlacklistedToken



class TokenAuthentication(BaseTokenAuth):
    keyword = "Token"
