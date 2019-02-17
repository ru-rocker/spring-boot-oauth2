package com.rurocker.oauth2.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HelloController {

	// anyone can access this endpoint
	@GetMapping(path = "/insecure/hello")
	public String getInsecureHello() {
		return "Hello Insecure";
	}

	// only authenticated users with role USER 
	// and scope read can access this
	@GetMapping(path = "/secure/hello")
	@PreAuthorize("hasRole('USER') and #oauth2.hasScope('read')")
	public String getSecureHello() {
		return "Hello Secure";
	}

	// only authenticated users with role USER 
	// and scope trust can access this.
	// Currently no scope trust, so this endpoint will be unavailable for any user.
	@GetMapping(path = "/secure/trust/hello")
	@PreAuthorize("hasRole('USER') and #oauth2.hasScope('trust')")
	public String getTrustHello() {
		return "Hello Trust";
	}
}
