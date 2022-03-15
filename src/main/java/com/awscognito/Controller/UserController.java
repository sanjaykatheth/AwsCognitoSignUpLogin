package com.awscognito.Controller;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.CodeDeliveryDetailsType;
import com.amazonaws.services.cognitoidp.model.CodeDeliveryFailureException;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpRequest;
import com.amazonaws.services.cognitoidp.model.ConfirmSignUpResult;
import com.amazonaws.services.cognitoidp.model.ExpiredCodeException;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordRequest;
import com.amazonaws.services.cognitoidp.model.ForgotPasswordResult;
import com.amazonaws.services.cognitoidp.model.InvalidParameterException;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.amazonaws.services.cognitoidp.model.UsernameExistsException;
import com.awscognito.Controller.service.UserService;
import com.awscognito.model.ConfirmPassword;
import com.awscognito.model.MessageResponse;
import com.awscognito.model.MyForgetPassword;
import com.awscognito.model.UserSignInRequest;
import com.awscognito.model.UserSignInResponse;
import com.awscognito.model.UserSignUpRequest;
import com.awscognito.model.VerifyEmail;

@RestController
@RequestMapping(path = "/api")
public class UserController {

	@Autowired
	private  AWSCognitoIdentityProvider cognitoClient;

	@Value(value = "${aws.cognito.userPoolId}")
	private  String userPoolId;
	@Value(value = "${aws.cognito.clientId}")
	private  String clientId;
	@Value(value = "${aws.cognito.clientSecret}")
	private  String clientSecret;

	@Autowired
	private UserService userService;

	@PostMapping(path = "/signUp")
	public ResponseEntity<?> signUp(@RequestBody  UserSignUpRequest userSignUpRequest) 

	{

		MessageResponse msgres=new MessageResponse();
		try {

			String mobile=userSignUpRequest.getMobile_no();
			String email=userSignUpRequest.getEmail();
			String password=userSignUpRequest.getPassword();
			SignUpRequest signUpRequest = new SignUpRequest();

			signUpRequest.setClientId(clientId);
			signUpRequest.setSecretHash(calculateSecretHash(clientId, clientSecret, email));
			signUpRequest.setUsername(email);
			signUpRequest.setPassword(password);

			List<AttributeType> attributeTypeList = new ArrayList<>();
			attributeTypeList.add(new AttributeType().withName("email").withValue(email));
			attributeTypeList.add( new AttributeType().withName("phone_number").withValue(mobile));
			signUpRequest.setUserAttributes(attributeTypeList);

			SignUpResult signUpResult = cognitoClient.signUp(signUpRequest);

			userService.saveUser(userSignUpRequest);
		}

		catch(CodeDeliveryFailureException e)
		{
			System.out.print("error message"+e.getErrorMessage());
		}
		catch(UsernameExistsException e)
		{
			String erromessage=e.getErrorMessage();
			msgres.setMessage(erromessage);
			return ResponseEntity.ok(msgres);

		}
		catch(Exception e)
		{

			return ResponseEntity.ok(e.getMessage());
		}
		msgres.setMessage("User Register Successfully");

		return ResponseEntity.ok(msgres);
	}

	@PostMapping("/verify")
	@ResponseBody
	public ResponseEntity<?> verifyEmail(@RequestBody VerifyEmail confirmCode) {
		ConfirmSignUpResult confirmSignUpResult = null;
		MessageResponse msgres=new MessageResponse();
		ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest();

		try
		{

			confirmSignUpRequest.setConfirmationCode(confirmCode.getConfirmCode());
			confirmSignUpRequest.setClientId(clientId);
			confirmSignUpRequest.setSecretHash(calculateSecretHash(clientId, clientSecret, confirmCode.getEmail()));
			confirmSignUpRequest.setUsername(confirmCode.getEmail());
			confirmSignUpResult = cognitoClient.confirmSignUp(confirmSignUpRequest);

		}
		catch (ExpiredCodeException e) {

			String errormsg=e.getErrorMessage();
			msgres.setMessage(errormsg);
			return ResponseEntity.ok(msgres);
		}
		catch(Exception e)
		{
			String errormsg=e.getMessage();
			msgres.setMessage(errormsg);
			return ResponseEntity.ok(msgres);
		}
		return ResponseEntity.ok("User Verfiy Succefully");


	}

	@PostMapping("/login")
	@ResponseBody
	public ResponseEntity<?> login(@RequestBody UserSignInRequest userSignInReq)

	{
		MessageResponse msgres=new MessageResponse();
		UserSignInResponse userSignInResponse = new UserSignInResponse();

		try
		{

			final	AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest();
			Map<String, String> authParamMap = new HashMap<>();
			authParamMap.put("USERNAME", userSignInReq.getEmail());
			authParamMap.put("PASSWORD", userSignInReq.getPassword());
			authParamMap.put("SECRET_HASH", calculateSecretHash(clientId, clientSecret,userSignInReq.getEmail()));

			adminInitiateAuthRequest.setAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH);
			adminInitiateAuthRequest.setClientId(clientId);
			adminInitiateAuthRequest.setUserPoolId(userPoolId);

			adminInitiateAuthRequest.setAuthParameters(authParamMap);
			AdminInitiateAuthResult adminInitiateAuthResult=cognitoClient.adminInitiateAuth(adminInitiateAuthRequest);
			AuthenticationResultType authenticationResultType = adminInitiateAuthResult.getAuthenticationResult();

			userSignInResponse.setAccessToken(authenticationResultType.getAccessToken());
			userSignInResponse.setIdToken(authenticationResultType.getIdToken());
			userSignInResponse.setRefreshToken(authenticationResultType.getRefreshToken());
			userSignInResponse.setExpiresIn(authenticationResultType.getExpiresIn());
			userSignInResponse.setTokenType(authenticationResultType.getTokenType());

		}
		catch (InvalidParameterException e) {
			String 	errormessage=e.getErrorMessage();
			msgres.setMessage(errormessage);
			return ResponseEntity.ok(msgres);


		} catch (Exception e) {

			String errormessage=e.getMessage();
			msgres.setMessage(errormessage);


			return ResponseEntity.ok(msgres);

		}

		return ResponseEntity.ok(userSignInResponse);



	}


	public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String userName)
	{
		final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

		SecretKeySpec signingKey = new SecretKeySpec(
				userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
				HMAC_SHA256_ALGORITHM);
		try {
			Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
			mac.init(signingKey);
			mac.update(userName.getBytes(StandardCharsets.UTF_8));
			byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(rawHmac);
		} catch (Exception e) {
			throw new RuntimeException("Error while calculating ");
		}
	}


	@ResponseBody
	@PostMapping("/forgotpassword")
	public ResponseEntity<?> forgetPassword(@RequestBody MyForgetPassword forgetReq) 
	{
		CodeDeliveryDetailsType codeDeliveryDetails=null;

		ForgotPasswordRequest forgetPassword=new ForgotPasswordRequest();
		forgetPassword.setClientId(clientId);
		forgetPassword.setSecretHash(calculateSecretHash(clientId, clientSecret, forgetReq.getEmail()));
		forgetPassword.setUsername(forgetReq.getEmail());
		ForgotPasswordResult forgetPasswordResult = cognitoClient.forgotPassword(forgetPassword);
		codeDeliveryDetails = forgetPasswordResult.getCodeDeliveryDetails();
		return ResponseEntity.ok(forgetPasswordResult);
	}



	@PostMapping("/confirmpassword")
	@ResponseBody
	public ResponseEntity<?> confirmPassword(@RequestBody ConfirmPassword confirm )
	{
		ConfirmForgotPasswordResult confirmForgotPasswordResult=null;

		MessageResponse msgres=new MessageResponse();

		try {


			ConfirmForgotPasswordRequest confirmForgotPasswordRequest=new ConfirmForgotPasswordRequest();
			confirmForgotPasswordRequest.setClientId(clientId);
			confirmForgotPasswordRequest.setSecretHash(calculateSecretHash(clientId, clientSecret, confirm.getEmail()));
			confirmForgotPasswordRequest.setConfirmationCode(confirm.getConfirmCode());
			confirmForgotPasswordRequest.setUsername(confirm.getEmail());
			confirmForgotPasswordRequest.setPassword(confirm.getNewpassword());
			confirmForgotPasswordResult = cognitoClient.confirmForgotPassword(confirmForgotPasswordRequest);


		}
		catch (InvalidParameterException e) {
			String 	errormessage=e.getErrorMessage();
			msgres.setMessage(errormessage);
			return ResponseEntity.ok(msgres);


		} catch (Exception e) {

			String errormessage=e.getMessage();
			msgres.setMessage(errormessage);
			return ResponseEntity.ok(msgres);

		}
		return ResponseEntity.ok(confirmForgotPasswordResult);

	}



}