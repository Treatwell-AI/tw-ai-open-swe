import { NextRequest, NextResponse } from "next/server";
import {
  GITHUB_TOKEN_COOKIE,
  GITHUB_INSTALLATION_ID_COOKIE,
} from "@openswe/shared/constants";
import { verifyGithubUser } from "@openswe/shared/github/verify-user";

/**
 * Checks basic authentication credentials against environment variables
 */
function checkBasicAuth(request: NextRequest): NextResponse | null {
  const basicAuthUser = process.env.BASIC_AUTH_USER;
  const basicAuthPass = process.env.BASIC_AUTH_PASS;

  // Skip basic auth if environment variables are not configured
  if (!basicAuthUser || !basicAuthPass) {
    return null;
  }

  const authHeader = request.headers.get("authorization");

  // Return 401 if no authorization header is present
  if (!authHeader) {
    return new NextResponse("Authentication required", {
      status: 401,
      headers: {
        "WWW-Authenticate": "Basic realm=\"Secure Area\"",
      },
    });
  }

  // Check if it's a Basic auth header
  if (!authHeader.startsWith("Basic ")) {
    return new NextResponse("Authentication required", {
      status: 401,
      headers: {
        "WWW-Authenticate": "Basic realm=\"Secure Area\"",
      },
    });
  }

  // Extract and decode credentials
  const base64Credentials = authHeader.slice(6); // Remove "Basic " prefix
  let credentials: string;
  
  try {
    credentials = Buffer.from(base64Credentials, "base64").toString("utf-8");
  } catch (error) {
    return new NextResponse("Invalid credentials format", {
      status: 401,
      headers: {
        "WWW-Authenticate": "Basic realm=\"Secure Area\"",
      },
    });
  }

  const [username, password] = credentials.split(":");

  // Validate credentials
  if (username !== basicAuthUser || password !== basicAuthPass) {
    return new NextResponse("Invalid credentials", {
      status: 401,
      headers: {
        "WWW-Authenticate": "Basic realm=\"Secure Area\"",
      },
    });
  }

  // Authentication successful
  return null;
}

export async function middleware(request: NextRequest) {
  // First layer: Basic authentication check
  const basicAuthResponse = checkBasicAuth(request);
  if (basicAuthResponse) {
    return basicAuthResponse;
  }

  // Second layer: Existing GitHub OAuth logic
  const token = request.cookies.get(GITHUB_TOKEN_COOKIE)?.value;
  const installationId = request.cookies.get(
    GITHUB_INSTALLATION_ID_COOKIE,
  )?.value;
  const user = token && installationId ? await verifyGithubUser(token) : null;

  if (request.nextUrl.pathname === "/") {
    if (user) {
      const url = request.nextUrl.clone();
      url.pathname = "/chat";
      return NextResponse.redirect(url);
    }
  }

  if (request.nextUrl.pathname.startsWith("/chat")) {
    if (!user) {
      const url = request.nextUrl.clone();
      url.pathname = "/";
      return NextResponse.redirect(url);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api/auth|webhooks/github|_next/static|_next/image|favicon.ico|logo.svg).*)"],
};


