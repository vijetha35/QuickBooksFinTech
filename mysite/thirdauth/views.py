# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from quickbooks import *
from django.shortcuts import redirect,render
from django.http import HttpResponse
from django.template.context import RequestContext
from thirdauth import getDiscoveryDocument
from django.conf import settings
from thirdauth.services import *
import urllib
import requests
import base64
import json
import random
from jose import jws, jwk
from base64 import urlsafe_b64decode, b64decode

#def signInWithIntuit(request):

def home(request):
	return render(request, 'home.html')

def connectToQuickbooks(request):
    url = getDiscoveryDocument.auth_endpoint
    params = {'scope' : settings.ACCOUNTING_SCOPE, 'redirect_uri' : settings.REDIRECT_URI,'response_type':'code','state': get_CSRF_token(request), 'client_id': settings.CLIENT_ID}
    url += '?' + urllib.urlencode(params)
    return redirect(url)
def connected(request):
    access_token = request.session.get('accessToken',None)
    if access_token is None:
        return HttpResponse('Your Bearer token has expired, please initiate Sign In With Intuit flow again')

    refresh_token = request.session.get('refreshToken',None)
    realmId = request.session['realmId']
    if realmId is None:
        user_profile_response, status_code = getUserProfile(access_token)

        if status_code >= 400:
        # if call to User Profile Service doesn't succeed then get a new bearer token from refresh token and try again
            bearer = getBearerTokenFromRefreshToken(refresh_token)
            user_profile_response, status_code = getUserProfile(bearer.accessToken)
            updateSession(request,bearer.accessToken,bearer.refreshToken,request.session.get('realmId',None),name=user_profile_response.get('givenName',None))

            if status_code >= 400:
                return HttpResponseServerError()
        c = {
            'first_name': user_profile_response.get('givenName',' '),
        }
    else:
        if request.session.get('name') is None:
            name = ''
        else:
            name = request.session.get('name')
        c = {
        'first_name': name,
        }

    return render(request, 'connected.html', context=c)

def disconnect(request):
    access_token = request.session.get('accessToken',None)
    refresh_token = request.session.get('refreshToken',None)

    revoke_response = ''
    if not access_token is None:
        revoke_response = revokeToken(access_token)
    elif not refresh_token is None:
        revoke_response = revokeToken(refresh_token)
    else:
        return HttpResponse('No accessToken or refreshToken found, Please connect again')

    request.session.flush()
    return HttpResponse(revoke_response)

def refreshTokenCall(request):
    refresh_token = request.session.get('refreshToken',None)
    if refresh_token is None:
        return HttpResponse('Not authorized')
    first_name = request.session.get('name',None)
    bearer = getBearerTokenFromRefreshToken(refresh_token)

    if isinstance(bearer, str):
        return HttpResponse(bearer)
    else:
        return HttpResponse('Access Token: '+bearer.accessToken+', Refresh Token: '+bearer.refreshToken)
        
def apiCall(request):
    access_token = request.session.get('accessToken',None)
    if access_token is None:
        return HttpResponse('Your Bearer token has expired, please initiate C2QB flow again')

    realmId = request.session['realmId']
    if realmId is None:
        return HttpResponse('No realm ID. QBO calls only work if the accounting scope was passed!')

    refresh_token = request.session['refreshToken']
    company_info_response, status_code = getCompanyInfo(access_token,realmId)

    if status_code >= 400:
        # if call to QBO doesn't succeed then get a new bearer token from refresh token and try again
        bearer = getBearerTokenFromRefreshToken(refresh_token)
        updateSession(request,bearer.accessToken,bearer.refreshToken,realmId)
        company_info_response, status_code = getCompanyInfo(bearer.accessToken,realmId)
        if status_code >= 400:
            return HttpResponseServerError()
    company_name = company_info_response['CompanyInfo']['CompanyName']
    address = company_info_response['CompanyInfo']['CompanyAddr']
    return HttpResponse('Company Name: '+company_name+', Company Address: '+address['Line1']+', '+address['City'] + ', ' + ' ' + address['PostalCode'])

def get_CSRF_token(request):
    token = request.session.get('csrfToken',None)
    if token is None:
        token = getSecretKey()
        request.session['csrfToken'] = token
    return token

def updateSession(request,access_token,refresh_token,realmId, name=None):
    request.session['accessToken'] = access_token
    request.session['refreshToken'] = refresh_token
    request.session['realmId'] = realmId
    request.session['name'] = name

def authCodeHandler(request):
    state = request.GET.get('state', None)
    error = request.GET.get('error', None)
    if error == 'access_denied':
        return redirect('home')
    if state is None:
        return HttpResponseBadRequest()
    elif state != get_CSRF_token(request): #validate against CSRF attacks
        return HttpResponse('unauthorized', status=401) 

    auth_code = request.GET.get('code', None)
    if auth_code is None:
        return HttpResponseBadRequest()

    bearer = getBearerToken(auth_code)
    realmId = request.GET.get('realmId',None)
    updateSession(request,bearer.accessToken,bearer.refreshToken,realmId)

    # Validate JWT tokens only for OpenID scope
    if bearer.idToken is not None:
        if not validateJWTToken(bearer.idToken):
            return HttpResponse('JWT Validation failed. Please try signing in again.')
        else:
            return redirect('connected')
    else:
        return redirect('connected')	

def signInWithIntuit(request):
	
	url = getDiscoveryDocument.auth_endpoint
	scope = ' '.join(settings.OPENID_SCOPES) 
	params = {'scope' : scope, 'redirect_uri' : settings.REDIRECT_URI,'response_type':'code','state': get_CSRF_token(request), 'client_id': settings.CLIENT_ID}
	url += '?' + urllib.urlencode(params)
	return redirect(url)
	'''consumerKey =           "Q0eWglqUf3EMddobBwmkq3H6s1nVMMnavf7cvSTWSIrqQLw2Tm"
	consumerSecret =        "CkTi2UXHcHwBU8wHM2K0733dcdx5jLSS0gIy3aKv"
	callbackUrl =           "https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl"
	port =8080
	session_manager = Oauth2SessionManager(
		sandbox=True,
		client_id=consumerKey,
		client_secret=consumerSecret,
		base_url='http://127.0.0.1:8080',
	)
	callback_url = 'http://127.0.0.1:8080' # Quickbooks will send the response to this url
	realm_id=123145939558809
	qb_data = {
                'authorize_url': session_manager.get_authorize_url(callback_url),
                'access_token': session_manager.access_token,
                'refresh_token': session_manager.refresh_token,
                'consumer_key': consumerKey,
                'consumer_secret': consumerSecret,
                'token_type': session_manager.token_type,
                'expires_in': session_manager.expires_in,
                'x_refresh_token_expires_in': session_manager.x_refresh_token_expires_in,
                'sandbox': True,
                'oauth_version': 2,
                'callback_url': 'http://localhost:{0}'.format(port),
                'base_url': 'http://localhost:{0}'.format(port),
            }
   	session_manager2 = Oauth2SessionManager(
	sandbox=True,
		client_id=realm_id,
		client_secret=CLIENT_SECRET,
		access_token=qb_data['access_token'],
	)
	client = QuickBooks(
	sandbox=True,
	session_manager=session_manager2,
	company_id=realm_id
	)'''


	# authorize_url = session_manager.get_authorize_url(callback_url)
	# request_token = session_manager.request_token
	# request_token_secret = session_manager.request_token_secret
	# qbObject = QuickBooks(
	# 		sandbox=True,
	#         consumer_key = consumerKey,
	#         consumer_secret = consumerSecret,
	#         callback_url = callbackUrl,
	#         minorversion=4
	#         )
	

	# authorize_url = qbObject.get_authorize_url() # will create a service, and further set up the qbObject.

	# oauth_token = request.GET['oauth_token']
	# oauth_verifier = request.GET['oauth_verifier']
	# realm_id = request.GET['realmId']

	# session = qbObject.get_access_tokens(oauth_verifier)

	# # say you want access to the reports

	# reportType = "ProfitAndLoss"

	# # url = "https://quickbooks.api.intuit.com/v3/company/asdfasdfas/"
	# # url += "reports/%s" % reportType

	# r = session.request( #This is just a Rauth request
	#     "POST",
	#     url,
	#     header_auth = True,
	#     realm = realm_id,
	#     params={"format":"json"}
	#     )
	# print qbText
	#return render(request,'home.html',context)

	
# Create your views here.
