#	OAuth2

## OAuth in REST Applications

-	In a typical web application, authentication will be done by application user
-	In REST Application, one application will interact with another application
	-	And application is authenticating another application
-	When we use OAuth, applications will authenticate with authorization server
-	Authorization server knows about access details for entire organization
	-	username, password, roles
	
## OAuth2 Flow

-	If App1 wants to communicate with app2 then it will authenticate with Authorization server
-	Authorization server will give authorization token
-	App1 will use this authorization token will sending request to resource server
-	Resource Server will validate token with authorization server, if its valid then a App1 can access protected resources


##	OAuth2 Implementation Steps

-	We can implement OAuth2 in 3 Steps

	-	Create Spring Boot application with OAuth2 dependency
	
				<dependency>
					<groupId>org.springframework.security.oauth.boot</groupId>
					<artifactId>spring-security-oauth2-autoconfigure</artifactId>
					<version>2.1.4.RELEASE</version>
				</dependency>
				
	-	Configure Database Entities with Spring Data JPA repositories
		-	Use In Memory DB HSQLDB
	-	Configure AuthorizationServer, ResourceServer, and WebSecurityConfigurer
	-	Test the application with postman
	


##	Execution Flow of OAuth2

-	Client will make a request to authorization server http://localhost:8080/oauth/token 
-	Authorization server will send authorization token to client in response
-	Client will make requests to resource API's with token http://localhost:8080/hello/bharath
	-	Client will send token as Headers with name Authorization Bearer token
-	Resource Server will validate the token with AuthorizationServer server if valid then response back to the clien



##	Roles in OAuth2


-	OAuth defines four roles –

	-	Resource Owner – The user of the application.
	-	Client – the application (user is using) which require access to user data on the resource server.
	-	Resource Server – store user’s data and http services which can return user data to authenticated clients.
	-	Authorization Server – responsible for authenticating user’s identity and gives an authorization token. This token is accepted by resource server and validate your identity.

(https://cdn2.bharath.com/wp-content/uploads/2019/04/Oauth2-Flow.png)


##	Access Token vs Refresh Token

-	Access Token:

	-	An access token is a string representing an authorization issued to the client
	-	Tokens represent specific scopes and duration of access, granted by the resource owner, and enforced by the resource server and authorization server
	
-	Refresh token:
	-	Refresh token is issued (along with access token) to the client by the authorization server and is used to obtain a new access token when the current access token becomes invalid or expires
	
	
##	Oauth2 – Authorization Server Configuration

-	Use annotation @EnableAuthorizationServer and extend the class AuthorizationServerConfigurerAdapter

				@Configuration
				@EnableAuthorizationServer
				public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter
				{
					@Autowired
					private BCryptPasswordEncoder passwordEncoder;
				 
					@Override
					public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
						security
							.tokenKeyAccess("permitAll()")
							.checkTokenAccess("isAuthenticated()")
							.allowFormAuthenticationForClients();
					}
				 
					@Override
					public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
						clients
							.inMemory()
							.withClient("clientapp").secret(passwordEncoder.encode("123456"))
							.authorizedGrantTypes("password", "authorization_code", "refresh_token")
							.authorities("READ_ONLY_CLIENT")
							.scopes("read_profile_info")
							.resourceIds("oauth2-resource")
							.redirectUris("http://localhost:8081/login")
							.accessTokenValiditySeconds(120)
							.refreshTokenValiditySeconds(240000);
					}
				}



##	Oauth2 – Resource Server

-	use @EnableResourceServer annotation and extend the ResourceServerConfigurerAdapter class
-	Above config enable protection on all endpoints starting /api

				@Configuration
				@EnableResourceServer
				public class OAuth2ResourceServer extends ResourceServerConfigurerAdapter
				{
					@Override
					public void configure(HttpSecurity http) throws Exception {
						http
							.authorizeRequests()
							.antMatchers("/api/**").authenticated()
							.antMatchers("/").permitAll();
					}
		}


##	Oauth2 - WebSecurityConfig

-	The resource server also provide a mechanism to authenticate users themselves. It will be a form based login in most cases

			
			@Configuration
			@Order(1)
			public class SecurityConfig extends WebSecurityConfigurerAdapter {
			  
				@Override
				protected void configure(HttpSecurity http) throws Exception {
					http
						.antMatcher("/**")
							.authorizeRequests()
							.antMatchers("/oauth/authorize**", "/login**", "/error**")
							.permitAll()
						.and()
							.authorizeRequests()
							.anyRequest().authenticated()
						.and()
							.formLogin().permitAll();
				}
			  
				@Override
				protected void configure(AuthenticationManagerBuilder auth) throws Exception {
					auth
						.inMemoryAuthentication()
						.withUser("humptydumpty").password(passwordEncoder().encode("123456")).roles("USER");
				}
				  
				@Bean
				public BCryptPasswordEncoder passwordEncoder(){
					return new BCryptPasswordEncoder();
				}
			}

	


##	Oauth2 protected REST resources

			@Controller
			public class RestResource
			{
				@RequestMapping("/api/users/me")
				public ResponseEntity<UserProfile> profile()
				{
					//Build some dummy data to return for testing
					User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
					String email = user.getUsername() + "@iambharath.com";
			 
					UserProfile profile = new UserProfile();
					profile.setName(user.getUsername());
					profile.setEmail(email);
			 
					return ResponseEntity.ok(profile);
				}
			}



## Testing 


-	When we tri to access http://localhost:8080/api/users/me resource
	-	 it will bring login screen 
	-	Enter credentials
	
-	http://localhost:8080/oauth/authorize?client_id=clientapp&response_type=code&scope=read_profile_info
-	It will redirect to a URL like : http://localhost:8081/login?code=EAR76A. Here 'EAR76A' is authorization code for the third party application.
-	Get access token from authorization server

				http://localhost:8080/oauth/token
 
				Headers:
				 
				Content-Type: application/x-www-form-urlencoded
				authorization: Basic Y2xpZW50YXBwOjEyMzQ1Ng==
				 
				Form data - application/x-www-form-urlencoded:
				 
				grant_type=authorization_code
				code=EAR76A
				redirect_uri=http://localhost:8081/login
				
				
-	Authorization server will get token in response
			
			{
				"access_token": "59ddb16b-6943-42f5-8e2f-3acb23f8e3c1",
				"token_type": "bearer",
				"refresh_token": "cea0aa8f-f732-44fc-8ba3-5e868d94af64",
				"expires_in": 4815,
				"scope": "read_profile_info"
			}
-	Access user data from resource server

		curl -X GET http://localhost:8080/api/users/me
			-H "authorization: Bearer 59ddb16b-6943-42f5-8e2f-3acb23f8e3c1"
