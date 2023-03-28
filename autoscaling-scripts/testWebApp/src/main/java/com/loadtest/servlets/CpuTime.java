/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 * Licensed under the Universal Permissive License v1.0 as shown at https://oss.oracle.com/licenses/upl.
 */

package com.loadtest.servlets;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Arrays;
import java.util.Set;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.naming.InitialContext;


/**
 * Servlet implementation class CPULoader
 */
@WebServlet("/CpuTime")
public class CpuTime extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final Integer FIB_SERIES = 40;
	private static AtomicInteger fibCalculators = new AtomicInteger(0);
	private static Integer serverHitCount = new Integer(0);
    private static String SERVER_NAME = null;


	public void service(HttpServletRequest request, HttpServletResponse response)throws IOException {
		serverHitCount++;
		PrintWriter out = response.getWriter();
		out.println("<html><head><title>CpuTime</title></head><body>");
		String serverName = getServerName();
		out.println(serverName + ":Running Fibonacci Calculators:" + fibCalculators);

		calculateFibs();
		out.println("SUCCESS");
		out.println("</BODY></HTML>");
	}

	public static long fibonacci(long number) throws InterruptedException{
		if(number == 1 || number == 2){
			return 1;
		}
		return fibonacci(number-1) + fibonacci(number -2); //tail recursion
	}

	private void calculateFibs() {

		int total = fibCalculators.getAndIncrement();
		System.out.println("Thread " + Thread.currentThread().getName() + " started, Total is " + total);
		try {
			long fib = fibonacci(FIB_SERIES);

		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		fibCalculators.getAndDecrement();
	}

	public static String getServerName() {
		if(SERVER_NAME != null){
			return SERVER_NAME;
		}
		try {
			InitialContext ctx = new InitialContext();
			MBeanServer mbeanserver = (MBeanServer) ctx.lookup("java:comp/env/jmx/runtime");
			ObjectName wmQuery = new ObjectName("*:*,Type=WorkManagerRuntime");
			Set<ObjectName> wmMBeanNames = mbeanserver.queryNames(null, wmQuery);
			for (ObjectName wmMBeanName : wmMBeanNames) {
				String svrRuntimeName = wmMBeanName.getKeyProperty("ServerRuntime");
				if (svrRuntimeName != null) {
					SERVER_NAME = svrRuntimeName;
					return svrRuntimeName;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "dummy";
	}
}
