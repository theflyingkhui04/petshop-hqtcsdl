// Authentication service for user management and role-based access control
const API_URL = "http://localhost:8080/api" // Change to your Spring Boot backend URL

// Add these variables to prevent redirect loops and track auth state
let isNavigating = false;
let authInitialized = false;
let redirectionInProgress = false;
let lastPathChecked = '';

// Token management
function getToken() {
  return localStorage.getItem("authToken") || sessionStorage.getItem("authToken")
}

function saveToken(token, rememberMe) {
  if (rememberMe) {
    localStorage.setItem("authToken", token)
  } else {
    sessionStorage.setItem("authToken", token)
  }
}

function clearToken() {
  localStorage.removeItem("authToken")
  sessionStorage.removeItem("authToken")
}

// JWT token parsing
function parseJwt(token) {
  try {
    const base64Url = token.split(".")[1]
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/")
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join(""),
    )
    return JSON.parse(jsonPayload)
  } catch (error) {
    console.error("Error parsing JWT token:", error)
    return null
  }
}

// Authentication functions
async function login(username, password, rememberMe = false) {
  try {
    // Call login API from Spring Boot backend
    const response = await fetch(`${API_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      credentials: "include",
    })

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.message || "Login failed")
    }

    const data = await response.json()
    const token = data.token || data.accessToken // Adjust based on your API response

    // Save token based on "Remember Me" checkbox
    saveToken(token, rememberMe)

    // Get user info from token
    const userData = parseJwt(token)

    // Set flag to prevent multiple redirects
    redirectionInProgress = true;

    // Redirect based on role
    if (hasRole("ADMIN", userData)) {
      window.location.href = "admin.html"
    } else {
      window.location.href = "index.html"
    }

    return { success: true }
  } catch (error) {
    console.error("Login error:", error)
    return { success: false, message: error.message }
  }
}

async function register(userData) {
  try {
    // Call register API from Spring Boot backend
    const response = await fetch(`${API_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: userData.username || userData.userName,
        email: userData.email,
        phoneNumber: userData.phoneNumber,
        password: userData.password,
        // Other fields if needed
      }),
    })

    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.message || "Registration failed")
    }

    return { success: true }
  } catch (error) {
    console.error("Registration error:", error)
    return { success: false, message: error.message }
  }
}

// Prevent multiple simultaneous logout attempts
let isLoggingOut = false;

function logout() {
  // Prevent multiple simultaneous logout attempts
  if (isLoggingOut) return;

  isLoggingOut = true;

  // Visual feedback - disable the button
  const logoutButtons = document.querySelectorAll(".logout-btn");
  logoutButtons.forEach(btn => {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging out...';
  });

  // You can call logout API if backend needs to invalidate token
  // fetch(`${API_URL}/auth/logout`, {
  //   method: "POST",
  //   headers: {
  //     "Authorization": `Bearer ${getToken()}`
  //   }
  // });

  clearToken()

  // Set flag to prevent multiple redirects
  redirectionInProgress = true;

  // Small delay to prevent flickering during redirect
  setTimeout(() => {
    window.location.href = "index.html";
    isLoggingOut = false;
  }, 300);
}

function isAuthenticated() {
  const token = getToken()
  if (!token) return false

  // Check if token is valid
  const userData = parseJwt(token)
  if (!userData) return false

  // Check if token is expired
  const currentTime = Date.now() / 1000
  if (userData.exp && userData.exp < currentTime) {
    clearToken()
    return false
  }

  return true
}

function getCurrentUser() {
  const token = getToken()
  if (!token) return null

  try {
    return parseJwt(token)
  } catch (error) {
    console.error("Error getting current user:", error)
    logout() // Invalid token, log out
    return null
  }
}

async function getUserProfile() {
  try {
    const response = await fetchWithAuth(`${API_URL}/users/profile`)

    if (!response.ok) {
      throw new Error("Could not get user information")
    }

    return await response.json()
  } catch (error) {
    console.error("Error fetching user profile:", error)
    return null
  }
}

function hasRole(role, userData = null) {
  const user = userData || getCurrentUser()
  if (!user) return false

  // Check in authorities array
  if (user.authorities && Array.isArray(user.authorities)) {
    return user.authorities.some((auth) => auth.authority === `ROLE_${role}` || auth.authority === role)
  }

  // Check role field
  if (user.role) {
    return user.role === role
  }

  // Check in roles array if present
  if (user.roles && Array.isArray(user.roles)) {
    return user.roles.includes(role) || user.roles.includes(`ROLE_${role}`)
  }

  return false
}

async function fetchWithAuth(url, options = {}) {
  const token = getToken()

  if (!token) {
    throw new Error("No authentication token")
  }

  const headers = {
    ...options.headers,
    Authorization: `Bearer ${token}`,
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (response.status === 401) {
      // Invalid or expired token
      logout()
      throw new Error("Session expired")
    }

    return response
  } catch (error) {
    console.error("API error:", error)
    throw error
  }
}

// Helper function to safely add event listeners without duplication
function addSingleEventListener(element, eventType, handler) {
  if (!element || !element.addEventListener) return;
  
  // Store event listeners on the element to track them
  if (!element._eventListeners) element._eventListeners = {};
  if (!element._eventListeners[eventType]) element._eventListeners[eventType] = [];
  
  // Check if this exact handler is already attached
  const existingIndex = element._eventListeners[eventType].indexOf(handler);
  if (existingIndex !== -1) return; // Already attached, do nothing
  
  // Add listener and track it
  element.addEventListener(eventType, handler);
  element._eventListeners[eventType].push(handler);
}

// Debugging helper
const DEBUG = false;
function debugLog(...args) {
  if (DEBUG) {
    console.log(`[AUTH ${new Date().toISOString()}]`, ...args);
  }
}

// Variables to prevent UI update loops
let isUpdatingUI = false;

function updateAuthUI() {
  // Prevent multiple simultaneous updates
  if (isUpdatingUI) return;
  isUpdatingUI = true;

  debugLog("Updating auth UI");
  const isLoggedIn = isAuthenticated();
  const user = getCurrentUser();

  // Elements to update
  const loginButtons = document.querySelectorAll(".login-button, .register-button");
  const userInfo = document.querySelectorAll(".user-info");
  const userNameElements = document.querySelectorAll("[data-user-name]");
  const logoutButtons = document.querySelectorAll(".logout-btn");
  const adminLinks = document.querySelectorAll(".admin-link");

  if (isLoggedIn && user) {
    // User is logged in
    loginButtons.forEach((el) => (el.style.display = "none"));
    userInfo.forEach((el) => (el.style.display = "block"));
    userNameElements.forEach((el) => (el.textContent = user.sub || user.username || "User"));

    // Only add event listeners once
    logoutButtons.forEach((el) => {
      el.style.display = "block";
      addSingleEventListener(el, "click", logout);
    });

    // Show admin link if user has admin role
    if (hasRole("ADMIN", user)) {
      adminLinks.forEach((el) => (el.style.display = "block"));
    } else {
      adminLinks.forEach((el) => (el.style.display = "none"));
    }
  } else {
    // User is not logged in
    loginButtons.forEach((el) => (el.style.display = "block"));
    userInfo.forEach((el) => (el.style.display = "none"));
    logoutButtons.forEach((el) => (el.style.display = "none"));
    adminLinks.forEach((el) => (el.style.display = "none"));
  }

  // Release the lock after a short delay
  setTimeout(() => {
    isUpdatingUI = false;
  }, 100);
}

// Function to check if redirection is needed based on current page and auth status
function checkAuthRedirect() {
  // Skip if redirection is already in progress
  if (redirectionInProgress) {
    debugLog("Redirection already in progress, skipping check");
    return;
  }

  const currentPath = window.location.pathname;
  
  // Skip if we've already checked this path recently
  if (currentPath === lastPathChecked) {
    debugLog("Path already checked recently, skipping redirect check");
    return;
  }
  
  lastPathChecked = currentPath;
  debugLog("Checking auth redirect for path:", currentPath);
  
  const isLoggedIn = isAuthenticated();
  const isAdmin = isLoggedIn && hasRole("ADMIN");
  
  // Admin page protection
  if (currentPath.includes('admin.html')) {
    if (!isLoggedIn) {
      debugLog("Not authenticated, redirecting to login");
      redirectionInProgress = true;
      window.location.href = "login.html";
      return;
    }

    if (!isAdmin) {
      debugLog("Not admin, redirecting to home");
      redirectionInProgress = true;
      window.location.href = "index.html";
      return;
    }
    
    debugLog("User is admin, staying on admin page");
  } 
  // Login page redirect if already logged in
  else if (currentPath.includes('login.html') && isLoggedIn) {
    if (isAdmin) {
      debugLog("Already authenticated as admin, redirecting to admin");
      redirectionInProgress = true;
      window.location.href = "admin.html";
      return;
    } else {
      debugLog("Already authenticated, redirecting to home");
      redirectionInProgress = true;
      window.location.href = "index.html";
      return;
    }
  }
  
  debugLog("No redirection needed");
}

// Reset redirection flag when page load is complete
window.addEventListener('load', function() {
  redirectionInProgress = false;
  debugLog("Page fully loaded, reset redirection flag");
});

// Initialize authentication state when page loads
document.addEventListener("DOMContentLoaded", () => {
  // Prevent multiple initializations
  if (authInitialized) return;
  authInitialized = true;
  
  debugLog("DOM loaded, initializing auth");
  
  // First update UI without redirection
  updateAuthUI();
  
  // Then check if redirection is needed
  // Use a slight delay to ensure any existing redirections have settled
  setTimeout(checkAuthRedirect, 100);
});

// Before page unload, set the navigation flag
window.addEventListener('beforeunload', function() {
  isNavigating = true;
});

// Export functions for use in other scripts
window.authService = {
  login,
  register,
  logout,
  isAuthenticated,
  getCurrentUser,
  getUserProfile,
  hasRole,
  fetchWithAuth,
  updateAuthUI,
};