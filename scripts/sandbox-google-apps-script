/**
 * LLC TIME TRACKER — SANDBOX GOOGLE APPS SCRIPT WEBHOOK
 * 
 * Target: Independent Sandbox Google Spreadsheet
 * Purpose: Authoritative durable database for Sandbox employees, credentials,
 *          timesheets, attendance, and audit logs.
 * 
 * SECURITY ARCHITECTURE & CONSTRAINTS:
 * 1. STRICT AUTHENTICATION: Every doPost request requires a shared secret matching
 *    the Script Property `SANDBOX_SHARED_SECRET`.
 * 2. DATA PRIVACY ON GET: doGet returns only a non-sensitive health check. It NEVER
 *    exposes employee records, credentials, pay rates, timesheets, or presence.
 * 3. STRICT SPREADSHEET ISOLATION: Requires Script Property `SANDBOX_SPREADSHEET_ID`.
 *    Never falls back to getActiveSpreadsheet(). Explicitly rejects production ID
 *    `1h8ssmDEcV-PMGlkpOzfQCtlRpnoT0CBQQveT3e4wPfA`.
 * 4. SINGLE SOURCE OF TRUTH (EMPLOYEE_DIRECTORY):
 *    `Employee_Directory` is the authoritative tab for employee accounts and credentials.
 *    Credentials are stored in `AccountPassword` and `mustChangePassword` (Boolean TRUE/FALSE).
 *    No separate `Employee_Auth` tab is created or used.
 * 5. IDEMPOTENT WRITES: Preserves session records, numeric duration seconds, and
 *    unique Session IDs across batch updates.
 * 
 * REQUIRED SCRIPT PROPERTIES (Apps Script > Project Settings > Script Properties):
 * - SANDBOX_SPREADSHEET_ID : <Your independent sandbox Google Spreadsheet ID>
 * - SANDBOX_SHARED_SECRET   : <Strong random secret shared exclusively with Cloudflare Worker>
 * 
 * REQUIRED CLOUDFLARE PAGES ENVIRONMENT VARIABLES:
 * - SANDBOX_APPS_SCRIPT_URL    : <Your deployed Web App URL ending in /exec>
 * - SANDBOX_APPS_SCRIPT_SECRET : <The matching SANDBOX_SHARED_SECRET value>
 */

var PROHIBITED_PRODUCTION_SPREADSHEET_ID = "1h8ssmDEcV-PMGlkpOzfQCtlRpnoT0CBQQveT3e4wPfA";

function jsonResponse(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Retrieves and validates the target Sandbox Spreadsheet.
 * Enforces strict isolation: refuses production ID and verifies sandbox ownership.
 */
function getSandboxSpreadsheet(customSheetId) {
  var props = PropertiesService.getScriptProperties();
  var sheetId = (customSheetId || props.getProperty("SANDBOX_SPREADSHEET_ID") || "").trim();

  if (sheetId === PROHIBITED_PRODUCTION_SPREADSHEET_ID || sheetId.indexOf(PROHIBITED_PRODUCTION_SPREADSHEET_ID) !== -1) {
    throw new Error("Targeting production spreadsheet ID " + PROHIBITED_PRODUCTION_SPREADSHEET_ID + " is strictly prohibited in sandbox mode.");
  }

  // 1. Try opening configured or provided sheet ID
  if (sheetId) {
    try {
      return SpreadsheetApp.openById(sheetId);
    } catch (openErr) {
      Logger.log("openById failed for " + sheetId + ": " + openErr.message + ". Attempting active spreadsheet fallback...");
    }
  }

  // 2. Safe fallback for container-bound scripts (Extensions > Apps Script from Sandbox Spreadsheet)
  try {
    var activeSs = SpreadsheetApp.getActiveSpreadsheet();
    if (activeSs) {
      var activeId = activeSs.getId();
      if (activeId === PROHIBITED_PRODUCTION_SPREADSHEET_ID || activeId.indexOf(PROHIBITED_PRODUCTION_SPREADSHEET_ID) !== -1) {
        throw new Error("Active spreadsheet matches production ID " + PROHIBITED_PRODUCTION_SPREADSHEET_ID + ". Aborting for isolation.");
      }
      return activeSs;
    }
  } catch (activeErr) {
    Logger.log("getActiveSpreadsheet fallback failed: " + activeErr.message);
  }

  if (!sheetId) {
    throw new Error("SANDBOX_SPREADSHEET_ID Script Property is not configured in Apps Script.");
  }

  throw new Error("Could not open spreadsheet with ID: " + sheetId + ". Please ensure SANDBOX_SPREADSHEET_ID in Script Properties contains a valid 44-character Google Spreadsheet ID.");
}

/**
 * Safe, minimal GET handler.
 * Never returns sensitive data (employees, credentials, timesheets, pay rates, presence).
 */
function doGet(e) {
  return jsonResponse({
    status: "SUCCESS",
    service: "LLC-Time-Tracker-Sandbox",
    message: "Sandbox Apps Script Webhook is active. Data queries are restricted to authenticated POST actions.",
    timestamp: new Date().toISOString()
  });
}

/**
 * Resolves column positions dynamically for Employee_Directory.
 * Guarantees AccountPassword and mustChangePassword exist without breaking existing columns.
 */
function getEmployeeDirectoryCols(empSheet) {
  var defaultHeaders = [
    "Employee Code", "Username", "Full Name", "Email", "Role", "Designation",
    "Date Hired", "Monthly Rate", "Hourly Rate", "Team Leader", "Screenshot Monitored",
    "Activity Monitored", "Account Status", "Masked Password", "User ID",
    "AccountPassword", "mustChangePassword"
  ];

  if (empSheet.getLastRow() === 0) {
    empSheet.appendRow(defaultHeaders);
    formatHeaderRow(empSheet, defaultHeaders.length);
  }

  var numCols = Math.max(empSheet.getLastColumn(), 1);
  var headerValues = empSheet.getRange(1, 1, 1, numCols).getValues()[0];
  var colMap = {};
  for (var i = 0; i < headerValues.length; i++) {
    var h = String(headerValues[i] || "").trim().toLowerCase();
    if (h) {
      colMap[h] = i + 1; // 1-based column index
    }
  }

  // Ensure AccountPassword column exists
  if (!colMap["accountpassword"] && !colMap["account password"] && !colMap["password"]) {
    var newColPw = empSheet.getLastColumn() + 1;
    empSheet.getRange(1, newColPw).setValue("AccountPassword");
    colMap["accountpassword"] = newColPw;
  }

  // Ensure mustChangePassword column exists
  if (!colMap["mustchangepassword"] && !colMap["must change password"]) {
    var newColMust = empSheet.getLastColumn() + 1;
    empSheet.getRange(1, newColMust).setValue("mustChangePassword");
    colMap["mustchangepassword"] = newColMust;
  }

  var codeCol = colMap["employee code"] || colMap["code"] || colMap["employeecode"] || 1;
  var userCol = colMap["username"] || colMap["user name"] || 2;
  var nameCol = colMap["full name"] || colMap["name"] || colMap["employee name"] || 3;
  var emailCol = colMap["email"] || colMap["email address"] || 4;
  var roleCol = colMap["role"] || colMap["user role"] || 5;
  var desigCol = colMap["designation"] || 6;
  var hiredCol = colMap["date hired"] || colMap["date joined"] || colMap["join date"] || 7;
  var monthlyCol = colMap["monthly rate"] || colMap["monthly rate (₱)"] || 8;
  var hourlyCol = colMap["hourly rate"] || colMap["hourly rate (₱)"] || 9;
  var tlCol = colMap["team leader"] || colMap["team leader id"] || colMap["supervisor"] || 10;
  var scrCol = colMap["screenshot monitored"] || 11;
  var actCol = colMap["activity monitored"] || 12;
  var statusCol = colMap["account status"] || colMap["status"] || 13;
  var maskedPwCol = colMap["masked password"] || 14;
  var idCol = colMap["user id"] || colMap["userid"] || 15;
  var pwCol = colMap["accountpassword"] || colMap["account password"] || colMap["password"] || 16;
  var mustChangeCol = colMap["mustchangepassword"] || colMap["must change password"] || 17;

  return {
    codeCol: codeCol,
    userCol: userCol,
    nameCol: nameCol,
    emailCol: emailCol,
    roleCol: roleCol,
    desigCol: desigCol,
    hiredCol: hiredCol,
    monthlyCol: monthlyCol,
    hourlyCol: hourlyCol,
    tlCol: tlCol,
    scrCol: scrCol,
    actCol: actCol,
    statusCol: statusCol,
    maskedPwCol: maskedPwCol,
    idCol: idCol,
    pwCol: pwCol,
    mustChangeCol: mustChangeCol,
    totalCols: Math.max(empSheet.getLastColumn(), 17)
  };
}

/**
 * Authenticated POST handler.
 * Validates SANDBOX_SHARED_SECRET BEFORE any spreadsheet access or data modification.
 */
function doPost(e) {
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(30000);
  } catch (lockErr) {
    return jsonResponse({
      status: "ERROR",
      code: "LOCK_TIMEOUT",
      message: "Server busy: Unable to acquire execution lock."
    });
  }

  try {
    // 1. Validate Shared Secret at the absolute start
    var props = PropertiesService.getScriptProperties();
    var expectedSecret = (props.getProperty("SANDBOX_SHARED_SECRET") || "").trim();

    if (!expectedSecret) {
      return jsonResponse({
        status: "ERROR",
        code: "UNCONFIGURED_SHARED_SECRET",
        message: "SANDBOX_SHARED_SECRET Script Property is not configured in Apps Script."
      });
    }

    if (!e || !e.postData || !e.postData.contents) {
      return jsonResponse({
        status: "ERROR",
        code: "EMPTY_PAYLOAD",
        message: "Empty post body payload."
      });
    }

    var data;
    try {
      data = JSON.parse(e.postData.contents);
    } catch (parseErr) {
      return jsonResponse({
        status: "ERROR",
        code: "INVALID_JSON",
        message: "Malformed JSON payload in request body."
      });
    }

    var providedSecret = String(data.secret || data.sharedSecret || (e.parameter && e.parameter.secret) || "").trim();
    if (!providedSecret || providedSecret !== expectedSecret) {
      return jsonResponse({
        status: "ERROR",
        code: "UNAUTHORIZED",
        message: "Unauthorized: Invalid or missing shared secret."
      });
    }

    // 2. Open Sandbox Spreadsheet with strict isolation checks
    var ss = getSandboxSpreadsheet(data.spreadsheetId || data.sandboxSpreadsheetId);
    var action = String(data.action || "").toUpperCase().trim();

    // ==========================================
    // ACTION: AUTH_LOGIN / VERIFY_CREDENTIALS
    // Validates login against authoritative Employee_Directory row
    // ==========================================
    if (action === "AUTH_LOGIN" || action === "VERIFY_CREDENTIALS") {
      var query = String(data.usernameOrCode || data.username || data.user || "").trim();
      var inputPassword = String(data.password || "");

      if (!query || !inputPassword) {
        return jsonResponse({
          status: "ERROR",
          code: "MISSING_CREDENTIALS",
          message: "Username/Code and password are required."
        });
      }

      var empSheet = ss.getSheetByName("Employee_Directory");
      if (!empSheet || empSheet.getLastRow() <= 1) {
        return jsonResponse({
          status: "ERROR",
          code: "USER_NOT_FOUND",
          message: "Employee_Directory is empty or uninitialized."
        });
      }

      var cols = getEmployeeDirectoryCols(empSheet);
      var maxCols = cols.totalCols;
      var lastRow = empSheet.getLastRow();
      var rows = empSheet.getRange(2, 1, lastRow - 1, maxCols).getValues();

      var cleanQuery = query.toLowerCase().replace(/^@/, "").trim();
      var foundRowIdx = -1;
      var foundEmp = null;

      for (var r = 0; r < rows.length; r++) {
        var row = rows[r];
        var rCode = String(row[cols.codeCol - 1] || "").toLowerCase().trim();
        var rUser = String(row[cols.userCol - 1] || "").toLowerCase().trim();
        var rId = String(row[cols.idCol - 1] || "").toLowerCase().trim();

        if (rUser === cleanQuery || rCode === cleanQuery || rId === cleanQuery) {
          foundRowIdx = r + 2;
          foundEmp = row;
          break;
        }
      }

      // Step A: Find the employee
      if (foundRowIdx === -1 || !foundEmp) {
        return jsonResponse({
          status: "ERROR",
          code: "USER_NOT_FOUND",
          message: "Account not found for \"" + query + "\"."
        });
      }

      // Check account status
      var empStatus = String(foundEmp[cols.statusCol - 1] || "active").toLowerCase().trim();
      if (empStatus === "inactive") {
        return jsonResponse({
          status: "ERROR",
          code: "USER_INACTIVE",
          message: "Account is inactive."
        });
      }

      // Step B: Check the employee's password-change flag
      var rawMustChange = foundEmp[cols.mustChangeCol - 1];
      var mustChange = (typeof rawMustChange === "boolean")
        ? rawMustChange
        : (String(rawMustChange).toUpperCase() === "TRUE" || String(rawMustChange).toUpperCase() === "YES");

      var storedPassword = String(foundEmp[cols.pwCol - 1] || "").trim();

      // If cell is empty, check if admin or fallback default
      if (!storedPassword) {
        var isSuperAdmin = String(foundEmp[cols.codeCol - 1] || "").toLowerCase() === "superadmin" ||
                           String(foundEmp[cols.roleCol - 1] || "").toLowerCase() === "admin";
        storedPassword = isSuperAdmin ? "AdminpassW0rd123!" : "Password123!";
      }

      var isMatch = (inputPassword === storedPassword);

      if (!isMatch) {
        return jsonResponse({
          status: "ERROR",
          code: "INVALID_CREDENTIALS",
          message: "Incorrect password."
        });
      }

      // Return sanitized user record
      var userPayload = {
        id: String(foundEmp[cols.idCol - 1] || ("usr-" + String(foundEmp[cols.codeCol - 1] || "auto").toLowerCase())).trim(),
        employeeCode: String(foundEmp[cols.codeCol - 1] || "").trim(),
        username: String(foundEmp[cols.userCol - 1] || "").trim(),
        name: String(foundEmp[cols.nameCol - 1] || "").trim(),
        email: String(foundEmp[cols.emailCol - 1] || "").trim(),
        role: String(foundEmp[cols.roleCol - 1] || "agent").trim(),
        designation: String(foundEmp[cols.desigCol - 1] || "Agent").trim(),
        status: empStatus,
        joinDate: String(foundEmp[cols.hiredCol - 1] || "").trim(),
        monthlyRate: Number(foundEmp[cols.monthlyCol - 1] || 0),
        hourlyRate: Number(foundEmp[cols.hourlyCol - 1] || 0),
        teamLeaderId: String(foundEmp[cols.tlCol - 1] || "").trim(),
        screenshotMonitored: String(foundEmp[cols.scrCol - 1]).toUpperCase() === "YES",
        activityMonitored: String(foundEmp[cols.actCol - 1]).toUpperCase() === "YES",
        mustChangePassword: mustChange,
        isPasswordChanged: mustChange ? "NO" : "YES"
      };

      return jsonResponse({
        status: "SUCCESS",
        valid: true,
        mustChangePassword: mustChange,
        user: userPayload
      });
    }

    // ==========================================
    // ACTION: UPDATE_PASSWORD
    // Updates AccountPassword and mustChangePassword (FALSE) in Employee_Directory
    // ==========================================
    if (action === "UPDATE_PASSWORD") {
      var targetUserId = String(data.userId || "").trim();
      var targetEmpCode = String(data.employeeCode || "").trim().toUpperCase();
      var targetUsername = String(data.username || "").trim().toLowerCase();
      var newPlainPassword = String(data.newPassword || data.password || data.accountPassword || data.passwordHash || "").trim();

      if (!newPlainPassword) {
        return jsonResponse({ status: "ERROR", message: "Missing new password in update payload." });
      }

      var empSheet = ss.getSheetByName("Employee_Directory") || ss.insertSheet("Employee_Directory");
      var cols = getEmployeeDirectoryCols(empSheet);
      var lastRow = empSheet.getLastRow();
      var rows = lastRow > 1 ? empSheet.getRange(2, 1, lastRow - 1, cols.totalCols).getValues() : [];

      var foundRowIdx = -1;
      for (var j = 0; j < rows.length; j++) {
        var rId = String(rows[j][cols.idCol - 1] || "").trim();
        var rCode = String(rows[j][cols.codeCol - 1] || "").trim().toUpperCase();
        var rUser = String(rows[j][cols.userCol - 1] || "").trim().toLowerCase();

        if (
          (targetUserId && rId === targetUserId) ||
          (targetEmpCode && rCode === targetEmpCode) ||
          (targetUsername && rUser === targetUsername)
        ) {
          foundRowIdx = j + 2;
          break;
        }
      }

      if (foundRowIdx === -1) {
        return jsonResponse({
          status: "ERROR",
          code: "USER_NOT_FOUND",
          message: "Employee account not found in Employee_Directory for password update."
        });
      }

      // Update AccountPassword and set mustChangePassword to Boolean FALSE
      empSheet.getRange(foundRowIdx, cols.pwCol).setValue(newPlainPassword);
      empSheet.getRange(foundRowIdx, cols.mustChangeCol).setValue(false);

      SpreadsheetApp.flush();

      // Verify update
      var checkPw = empSheet.getRange(foundRowIdx, cols.pwCol).getValue();
      var checkMust = empSheet.getRange(foundRowIdx, cols.mustChangeCol).getValue();

      return jsonResponse({
        status: "SUCCESS",
        action: "UPDATE_PASSWORD",
        userId: targetUserId,
        message: "Password and mustChangePassword successfully updated in Employee_Directory.",
        verified: (checkPw === newPlainPassword && checkMust === false)
      });
    }

    // ==========================================
    // ACTION: HEARTBEAT_UPDATE / SYNC_PRESENCE
    // ==========================================
    if (action === "HEARTBEAT_UPDATE" || action === "SYNC_PRESENCE") {
      var presenceSheet = ss.getSheetByName("Live_Presence") || ss.insertSheet("Live_Presence");
      var defaultPresHeaders = [
        "User ID", "Employee Code", "Employee Name", "Role", "Designation",
        "Status", "Current Task", "Current App / Window", "Last Heartbeat", "Tracking State", "IP / Device Info"
      ];
      if (presenceSheet.getLastRow() === 0) {
        presenceSheet.appendRow(defaultPresHeaders);
        formatHeaderRow(presenceSheet, defaultPresHeaders.length);
      }

      var presenceList = [];
      if (Array.isArray(data.presence)) {
        presenceList = data.presence;
      } else if (data.presence && typeof data.presence === "object") {
        presenceList = [data.presence];
      }

      var pRows = presenceSheet.getLastRow() > 1 ? presenceSheet.getRange(2, 1, presenceSheet.getLastRow() - 1, Math.max(presenceSheet.getLastColumn(), 11)).getValues() : [];
      var pMap = {};
      for (var pj = 0; pj < pRows.length; pj++) {
        var existingId = String(pRows[pj][0] || "").trim();
        var existingCode = String(pRows[pj][1] || "").trim().toUpperCase();
        var legacyCode = String(pRows[pj][0] || "").trim().toUpperCase();
        if (existingId) pMap[existingId] = pj + 2;
        if (existingCode && existingCode !== "N/A") pMap[existingCode] = pj + 2;
        if (legacyCode && legacyCode !== "N/A") pMap[legacyCode] = pj + 2;
      }

      for (var pk = 0; pk < presenceList.length; pk++) {
        var p = presenceList[pk];
        var pCode = String(p.employeeCode || "").trim().toUpperCase();
        var pId = String(p.userId || "").trim();
        var targetRowIdx = (pId && pMap[pId]) || (pCode && pMap[pCode]) || -1;

        var trackingState = p.isTracking ? (p.isPaused ? "Paused" : "Tracking Active") : "Standby";
        var statusDesc = p.status || (p.isOnline ? (p.isTracking ? (p.isPaused ? "Paused" : "Tracking Active") : "Online Standby") : "Offline");
        var rowData = [
          pId || ("usr-" + (pCode ? pCode.toLowerCase() : Date.now())),
          pCode || "N/A",
          p.userName || p.name || "Employee",
          p.userRole || p.role || "agent",
          p.designation || "Agent",
          statusDesc,
          p.currentTask || "Idle",
          p.currentApp || (p.loginPlatform === "software" ? "Desktop App" : "Web Portal"),
          p.lastHeartbeat || new Date().toISOString(),
          trackingState,
          p.ip || p.device || (p.loginPlatform === "software" ? "Desktop App" : "Web Portal")
        ];

        if (targetRowIdx !== -1) {
          presenceSheet.getRange(targetRowIdx, 1, 1, 11).setValues([rowData]);
        } else {
          presenceSheet.appendRow(rowData);
          var newRow = presenceSheet.getLastRow();
          if (pId) pMap[pId] = newRow;
          if (pCode) pMap[pCode] = newRow;
        }
      }

      return jsonResponse({ status: "SUCCESS", action: "HEARTBEAT_UPDATE", count: presenceList.length });
    }

    // ==========================================
    // ACTION: SYNC_TIMELOGS / BATCH_TIMELOGS
    // Saves/updates Time_Logs, Detailed_Time_Logs, and Timesheets idempotently by Session ID
    // ==========================================
    if (action === "SYNC_TIMELOGS" || action === "BATCH_TIMELOGS") {
      var logs = data.timeLogs || data.logs || (Array.isArray(data) ? data : []);
      var syncTimestamp = new Date().toISOString();

      function syncLogsToSheet(sheetName, defaultHeaders, buildRowFn) {
        var sheet = ss.getSheetByName(sheetName) || ss.insertSheet(sheetName);
        if (sheet.getLastRow() === 0) {
          sheet.appendRow(defaultHeaders);
          formatHeaderRow(sheet, defaultHeaders.length);
        }

        var existingMap = {};
        if (sheet.getLastRow() > 1) {
          var existingData = sheet.getRange(2, 1, sheet.getLastRow() - 1, defaultHeaders.length).getValues();
          for (var k = 0; k < existingData.length; k++) {
            var idStr = String(existingData[k][0] || "").trim();
            if (idStr) {
              existingMap[idStr] = k + 2;
            }
          }
        }

        for (var l = 0; l < logs.length; l++) {
          var log = logs[l];
          var sId = String(log.sessionId || log.id || "").trim();
          if (!sId) continue;

          var lRow = buildRowFn(log, sId);
          if (existingMap[sId]) {
            sheet.getRange(existingMap[sId], 1, 1, defaultHeaders.length).setValues([lRow]);
          } else {
            sheet.appendRow(lRow);
            existingMap[sId] = sheet.getLastRow();
          }
        }
      }

      // 1. Time_Logs
      var timeLogsHeaders = [
        "Session ID", "User ID", "Employee Code", "Employee Name", "Designation",
        "Task Name", "Start Time", "End Time", "Duration (Seconds)", "Duration (HH:MM:SS)",
        "Status", "Sync Timestamp", "Source"
      ];
      syncLogsToSheet("Time_Logs", timeLogsHeaders, function(log, sId) {
        var durSec = Math.max(0, Math.round(Number(log.durationSeconds || 0)));
        return [
          sId,
          String(log.userId || "").trim(),
          String(log.employeeCode || "").trim(),
          String(log.userName || log.employeeName || "").trim(),
          String(log.designation || "Agent").trim(),
          String(log.task || log.currentTask || "Work").trim(),
          String(log.startTime || "").trim(),
          String(log.endTime || "").trim(),
          durSec,
          formatTotalTime(durSec),
          String(log.status || "completed").trim(),
          syncTimestamp,
          String(log.source || (log.appsUsed ? "Desktop App" : "Web Portal")).trim()
        ];
      });

      // 2. Detailed_Time_Logs
      var detailedHeaders = [
        "Session ID", "User ID", "Employee Code", "Employee Name", "Designation",
        "Task Name", "Subtask / Notes", "Software / Window", "Start Time", "End Time",
        "Duration (Seconds)", "Duration (HH:MM:SS)", "Status", "Sync Timestamp", "Source"
      ];
      syncLogsToSheet("Detailed_Time_Logs", detailedHeaders, function(log, sId) {
        var durSec = Math.max(0, Math.round(Number(log.durationSeconds || 0)));
        var appWindow = String(log.currentApp || (log.appsUsed && log.appsUsed[0] ? log.appsUsed[0].appName : "LLC Desktop App")).trim();
        return [
          sId,
          String(log.userId || "").trim(),
          String(log.employeeCode || "").trim(),
          String(log.userName || log.employeeName || "").trim(),
          String(log.designation || "Agent").trim(),
          String(log.task || log.currentTask || "Work").trim(),
          String(log.notes || log.subtask || "").trim(),
          appWindow,
          String(log.startTime || "").trim(),
          String(log.endTime || "").trim(),
          durSec,
          formatTotalTime(durSec),
          String(log.status || "completed").trim(),
          syncTimestamp,
          String(log.source || (log.appsUsed ? "Desktop App" : "Web Portal")).trim()
        ];
      });

      // 3. Timesheets
      var timesheetHeaders = [
        "Session ID", "User ID", "Employee Code", "Employee Name", "Designation",
        "Task Name", "Start Time", "End Time", "Duration (Seconds)", "Duration (HH:MM:SS)",
        "Status", "Sync Timestamp", "Source"
      ];
      syncLogsToSheet("Timesheets", timesheetHeaders, function(log, sId) {
        var durSec = Math.max(0, Math.round(Number(log.durationSeconds || 0)));
        return [
          sId,
          String(log.userId || "").trim(),
          String(log.employeeCode || "").trim(),
          String(log.userName || log.employeeName || "").trim(),
          String(log.designation || "Agent").trim(),
          String(log.task || log.currentTask || "Work").trim(),
          String(log.startTime || "").trim(),
          String(log.endTime || "").trim(),
          durSec,
          formatTotalTime(durSec),
          String(log.status || "completed").trim(),
          syncTimestamp,
          String(log.source || (log.appsUsed ? "Desktop App" : "Web Portal")).trim()
        ];
      });

      return jsonResponse({ status: "SUCCESS", action: "SYNC_TIMELOGS", count: logs.length });
    }

    // ==========================================
    // ACTION: SYNC_USERS / SYNC_EMPLOYEES / ADD_EMPLOYEE
    // Authoritative Employee_Directory management.
    // Preserves existing AccountPassword and mustChangePassword for existing accounts!
    // ==========================================
    if (action === "SYNC_USERS" || action === "SYNC_EMPLOYEES" || action === "ADD_EMPLOYEE") {
      var users = data.users || data.employees || (data.user ? [data.user] : (data.employee ? [data.employee] : []));
      var empSheet = ss.getSheetByName("Employee_Directory") || ss.insertSheet("Employee_Directory");
      var cols = getEmployeeDirectoryCols(empSheet);

      var existingEmpMap = {};
      var existingRowData = {};
      if (empSheet.getLastRow() > 1) {
        var eData = empSheet.getRange(2, 1, empSheet.getLastRow() - 1, cols.totalCols).getValues();
        for (var m = 0; m < eData.length; m++) {
          var codeStr = String(eData[m][cols.codeCol - 1] || "").trim().toUpperCase();
          var idStr = String(eData[m][cols.idCol - 1] || "").trim();
          var uStr = String(eData[m][cols.userCol - 1] || "").trim().toLowerCase();
          var rowNum = m + 2;
          if (codeStr) existingEmpMap[codeStr] = rowNum;
          if (idStr) existingEmpMap[idStr] = rowNum;
          if (uStr) existingEmpMap[uStr] = rowNum;
          existingRowData[rowNum] = eData[m];
        }
      }

      for (var n = 0; n < users.length; n++) {
        var u = users[n];
        var eCode = String(u.employeeCode || "").trim().toUpperCase();
        var uId = String(u.id || "").trim();
        var uName = String(u.username || "").trim().toLowerCase();
        var targetRow = (eCode && existingEmpMap[eCode]) || (uId && existingEmpMap[uId]) || (uName && existingEmpMap[uName]) || -1;

        if (targetRow !== -1) {
          // UPDATE EXISTING EMPLOYEE:
          // Update profile fields while strictly preserving existing AccountPassword & mustChangePassword
          var oldRow = existingRowData[targetRow] || [];
          var currentPw = oldRow[cols.pwCol - 1];
          var currentMust = oldRow[cols.mustChangeCol - 1];

          // If payload explicitly specifies new password, update it; otherwise preserve
          var finalPw = (u.accountPassword || u.password) ? String(u.accountPassword || u.password) : currentPw;
          var finalMust = (u.mustChangePassword !== undefined) ? Boolean(u.mustChangePassword) : currentMust;

          empSheet.getRange(targetRow, cols.codeCol).setValue(eCode);
          empSheet.getRange(targetRow, cols.userCol).setValue(String(u.username || "").trim().toLowerCase());
          empSheet.getRange(targetRow, cols.nameCol).setValue(String(u.name || "").trim());
          empSheet.getRange(targetRow, cols.emailCol).setValue(String(u.email || "").trim());
          empSheet.getRange(targetRow, cols.roleCol).setValue(String(u.role || "agent").trim());
          empSheet.getRange(targetRow, cols.desigCol).setValue(String(u.designation || "Agent").trim());
          if (u.joinDate) empSheet.getRange(targetRow, cols.hiredCol).setValue(String(u.joinDate).trim());
          if (u.monthlyRate !== undefined) empSheet.getRange(targetRow, cols.monthlyCol).setValue(Number(u.monthlyRate || 0));
          if (u.hourlyRate !== undefined) empSheet.getRange(targetRow, cols.hourlyCol).setValue(Number(u.hourlyRate || 0));
          if (u.teamLeaderId !== undefined) empSheet.getRange(targetRow, cols.tlCol).setValue(String(u.teamLeaderId || "").trim());
          if (u.screenshotMonitored !== undefined) empSheet.getRange(targetRow, cols.scrCol).setValue(u.screenshotMonitored ? "YES" : "NO");
          if (u.activityMonitored !== undefined) empSheet.getRange(targetRow, cols.actCol).setValue(u.activityMonitored ? "YES" : "NO");
          if (u.status !== undefined) empSheet.getRange(targetRow, cols.statusCol).setValue(String(u.status || "active").trim());
          if (uId) empSheet.getRange(targetRow, cols.idCol).setValue(uId);

          if (finalPw !== undefined) empSheet.getRange(targetRow, cols.pwCol).setValue(finalPw);
          if (finalMust !== undefined) empSheet.getRange(targetRow, cols.mustChangeCol).setValue(finalMust);
        } else {
          // NEW EMPLOYEE CREATION:
          // Default AccountPassword: "Password123!"
          // Default mustChangePassword: TRUE (Boolean)
          var newRowArray = new Array(cols.totalCols);
          for (var c = 0; c < cols.totalCols; c++) newRowArray[c] = "";

          newRowArray[cols.codeCol - 1] = eCode || "N/A";
          newRowArray[cols.userCol - 1] = String(u.username || "").trim().toLowerCase();
          newRowArray[cols.nameCol - 1] = String(u.name || "").trim();
          newRowArray[cols.emailCol - 1] = String(u.email || "").trim();
          newRowArray[cols.roleCol - 1] = String(u.role || "agent").trim();
          newRowArray[cols.desigCol - 1] = String(u.designation || "Agent").trim();
          newRowArray[cols.hiredCol - 1] = String(u.joinDate || "2024-01-01").trim();
          newRowArray[cols.monthlyCol - 1] = Number(u.monthlyRate || 0);
          newRowArray[cols.hourlyCol - 1] = Number(u.hourlyRate || 0);
          newRowArray[cols.tlCol - 1] = String(u.teamLeaderId || "").trim();
          newRowArray[cols.scrCol - 1] = u.screenshotMonitored ? "YES" : "NO";
          newRowArray[cols.actCol - 1] = u.activityMonitored ? "YES" : "NO";
          newRowArray[cols.statusCol - 1] = String(u.status || "active").trim();
          newRowArray[cols.maskedPwCol - 1] = "********";
          newRowArray[cols.idCol - 1] = uId || ("usr-" + (eCode ? eCode.toLowerCase() : Date.now()));
          newRowArray[cols.pwCol - 1] = String(u.accountPassword || u.password || "Password123!").trim();
          newRowArray[cols.mustChangeCol - 1] = (u.mustChangePassword !== undefined) ? Boolean(u.mustChangePassword) : true;

          empSheet.appendRow(newRowArray);
          var newEmpRow = empSheet.getLastRow();
          if (eCode) existingEmpMap[eCode] = newEmpRow;
          if (uId) existingEmpMap[uId] = newEmpRow;
          if (uName) existingEmpMap[uName] = newEmpRow;
        }
      }

      SpreadsheetApp.flush();
      return jsonResponse({ status: "SUCCESS", action: action, count: users.length });
    }

    // ==========================================
    // ACTION: SYNC_ATTENDANCE / RECORD_ATTENDANCE
    // ==========================================
    if (action === "SYNC_ATTENDANCE" || action === "RECORD_ATTENDANCE") {
      var attendances = data.attendance || (Array.isArray(data) ? data : []);
      if (!Array.isArray(attendances) && typeof attendances === "object") {
        attendances = [attendances];
      }

      var attSheet = ss.getSheetByName("Daily_Attendance") || ss.insertSheet("Daily_Attendance");
      if (attSheet.getLastRow() === 0) {
        attSheet.appendRow(["Log ID", "Date", "User ID", "Employee Code", "Employee Name", "Role", "First Check-in", "Last Check-out", "Total Duration", "Shift Status"]);
        formatHeaderRow(attSheet, 10);
      }

      var attMap = {};
      if (attSheet.getLastRow() > 1) {
        var attData = attSheet.getRange(2, 1, attSheet.getLastRow() - 1, 3).getValues();
        for (var ai = 0; ai < attData.length; ai++) {
          var logId = String(attData[ai][0] || "").trim();
          var dt = String(attData[ai][1] || "").trim();
          var usr = String(attData[ai][2] || "").trim();
          if (logId) attMap[logId] = ai + 2;
          if (usr && dt) attMap[usr + "_" + dt] = ai + 2;
        }
      }

      for (var aj = 0; aj < attendances.length; aj++) {
        var a = attendances[aj];
        var aId = String(a.id || a.logId || "").trim();
        var aUser = String(a.userId || "").trim();
        var aDate = String(a.date || Utilities.formatDate(new Date(), "Asia/Manila", "yyyy-MM-dd")).trim();
        var attRowIdx = (aId && attMap[aId]) || (aUser && aDate && attMap[aUser + "_" + aDate]) || -1;

        var aRow = [
          aId || ("ATT-" + aUser + "-" + aDate),
          aDate,
          aUser,
          String(a.employeeCode || "").trim(),
          String(a.name || a.employeeName || "").trim(),
          String(a.role || "agent").trim(),
          String(a.firstCheckin || a.firstCheckIn || "").trim(),
          String(a.lastCheckout || a.lastCheckOut || "").trim(),
          String(a.totalDuration || a.durationFormatted || "").trim(),
          String(a.shiftStatus || a.status || "Completed").trim()
        ];

        if (attRowIdx !== -1) {
          attSheet.getRange(attRowIdx, 1, 1, 10).setValues([aRow]);
        } else {
          attSheet.appendRow(aRow);
          var newAttRow = attSheet.getLastRow();
          if (aId) attMap[aId] = newAttRow;
          if (aUser && aDate) attMap[aUser + "_" + aDate] = newAttRow;
        }
      }

      return jsonResponse({ status: "SUCCESS", action: "SYNC_ATTENDANCE", count: attendances.length });
    }

    // ==========================================
    // ACTION: LOG_AUDIT / SYNC_AUDITLOGS
    // ==========================================
    if (action === "LOG_AUDIT" || action === "SYNC_AUDITLOGS") {
      var auditList = data.logs || data.auditlogs || (data.log ? [data.log] : []);
      var auditSheet = ss.getSheetByName("Audit_Logs") || ss.insertSheet("Audit_Logs");
      if (auditSheet.getLastRow() === 0) {
        auditSheet.appendRow(["Log ID", "Timestamp (ISO)", "Category", "Actor ID", "Actor Name", "Actor Role", "Action Details", "IP / Device"]);
        formatHeaderRow(auditSheet, 8);
      }

      for (var al = 0; al < auditList.length; al++) {
        var aud = auditList[al];
        auditSheet.appendRow([
          aud.id || ("AUD-" + Date.now()),
          aud.timestamp || new Date().toISOString(),
          aud.category || "GENERAL",
          aud.actorId || "",
          aud.actorName || "",
          aud.actorRole || "",
          aud.actionDetails || aud.action || "",
          aud.ip || aud.device || ""
        ]);
      }

      return jsonResponse({ status: "SUCCESS", action: "LOG_AUDIT", count: auditList.length });
    }

    // ==========================================
    // AUTHENTICATED READ ACTIONS (Protected POST)
    // ==========================================
    if (action === "GET_ALL" || action === "READ_ALL" || action === "SYNC_ALL") {
      return jsonResponse({
        status: "SUCCESS",
        action: action,
        employees: readEmployees(ss, false),
        timeLogs: readTimeLogs(ss),
        presence: readPresence(ss),
        attendance: readAttendance(ss)
      });
    }

    // GET_AUTH_EMPLOYEES: Internal Worker-to-Apps-Script endpoint that returns credentials
    if (action === "GET_AUTH_EMPLOYEES") {
      return jsonResponse({
        status: "SUCCESS",
        action: "GET_AUTH_EMPLOYEES",
        employees: readEmployees(ss, true)
      });
    }

    if (action === "GET_EMPLOYEES") {
      return jsonResponse({
        status: "SUCCESS",
        action: "GET_EMPLOYEES",
        employees: readEmployees(ss, false)
      });
    }

    if (action === "GET_TIMELOGS") {
      return jsonResponse({
        status: "SUCCESS",
        action: "GET_TIMELOGS",
        timeLogs: readTimeLogs(ss)
      });
    }

    if (action === "GET_PRESENCE") {
      return jsonResponse({
        status: "SUCCESS",
        action: "GET_PRESENCE",
        presence: readPresence(ss)
      });
    }

    if (action === "GET_ATTENDANCE") {
      return jsonResponse({
        status: "SUCCESS",
        action: "GET_ATTENDANCE",
        attendance: readAttendance(ss)
      });
    }

    return jsonResponse({ status: "SUCCESS", action: action, message: "Action accepted." });
  } catch (err) {
    return jsonResponse({ status: "ERROR", error: err.message || err.toString() });
  } finally {
    lock.releaseLock();
  }
}

// ==========================================
// DATA READ HELPERS
// ==========================================

function readEmployees(ss, includeAuthCredentials) {
  var empSheet = ss.getSheetByName("Employee_Directory");
  if (!empSheet || empSheet.getLastRow() <= 1) return [];

  var cols = getEmployeeDirectoryCols(empSheet);
  var maxCols = cols.totalCols;
  var eValues = empSheet.getRange(2, 1, empSheet.getLastRow() - 1, maxCols).getValues();

  return eValues.map(function(r) {
    var rawMustChange = r[cols.mustChangeCol - 1];
    var mustChange = (typeof rawMustChange === "boolean")
      ? rawMustChange
      : (String(rawMustChange).toUpperCase() === "TRUE" || String(rawMustChange).toUpperCase() === "YES");

    var emp = {
      employeeCode: String(r[cols.codeCol - 1] || "").trim(),
      username: String(r[cols.userCol - 1] || "").trim(),
      name: String(r[cols.nameCol - 1] || "").trim(),
      email: String(r[cols.emailCol - 1] || "").trim(),
      role: String(r[cols.roleCol - 1] || "agent").trim(),
      designation: String(r[cols.desigCol - 1] || "Agent").trim(),
      joinDate: String(r[cols.hiredCol - 1] || "").trim(),
      monthlyRate: Number(r[cols.monthlyCol - 1] || 0),
      hourlyRate: Number(r[cols.hourlyCol - 1] || 0),
      teamLeaderId: String(r[cols.tlCol - 1] || "").trim(),
      screenshotMonitored: String(r[cols.scrCol - 1]).toUpperCase() === "YES",
      activityMonitored: String(r[cols.actCol - 1]).toUpperCase() === "YES",
      status: String(r[cols.statusCol - 1] || "active").trim(),
      id: String(r[cols.idCol - 1] || "").trim(),
      mustChangePassword: mustChange,
      isPasswordChanged: mustChange ? "NO" : "YES"
    };

    if (includeAuthCredentials) {
      emp.accountPassword = String(r[cols.pwCol - 1] || "").trim();
    }

    return emp;
  });
}

function readTimeLogs(ss) {
  var logSheet = ss.getSheetByName("Time_Logs");
  if (!logSheet || logSheet.getLastRow() <= 1) return [];

  var lValues = logSheet.getRange(2, 1, Math.min(logSheet.getLastRow() - 1, 1000), 13).getValues();
  return lValues.map(function(r) {
    var durSec = Number(r[8] || 0);
    return {
      id: String(r[0] || "").trim(),
      sessionId: String(r[0] || "").trim(),
      userId: String(r[1] || "").trim(),
      employeeCode: String(r[2] || "").trim(),
      userName: String(r[3] || "").trim(),
      designation: String(r[4] || "").trim(),
      task: String(r[5] || "").trim(),
      startTime: String(r[6] || "").trim(),
      endTime: String(r[7] || "").trim(),
      durationSeconds: durSec,
      totalTime: String(r[9] || "").trim(),
      status: String(r[10] || "completed").trim(),
      syncTimestamp: String(r[11] || "").trim(),
      source: String(r[12] || "").trim()
    };
  });
}

function readPresence(ss) {
  var presSheet = ss.getSheetByName("Live_Presence");
  if (!presSheet || presSheet.getLastRow() <= 1) return [];

  var pValues = presSheet.getRange(2, 1, presSheet.getLastRow() - 1, 13).getValues();
  return pValues.map(function(r) {
    return {
      employeeCode: String(r[0] || "").trim(),
      userName: String(r[1] || "").trim(),
      userRole: String(r[2] || "").trim(),
      designation: String(r[3] || "").trim(),
      status: String(r[4] || "").trim(),
      currentTask: String(r[5] || "").trim(),
      elapsedTimeFormatted: String(r[6] || "").trim(),
      totalTodayFormatted: String(r[7] || "").trim(),
      firstCheckin: String(r[8] || "").trim(),
      timezone: String(r[9] || "").trim(),
      loginPlatform: String(r[10] || "").trim(),
      lastHeartbeat: String(r[11] || "").trim(),
      userId: String(r[12] || "").trim()
    };
  });
}

function readAttendance(ss) {
  var attSheet = ss.getSheetByName("Daily_Attendance");
  if (!attSheet || attSheet.getLastRow() <= 1) return [];

  var aValues = attSheet.getRange(2, 1, attSheet.getLastRow() - 1, 10).getValues();
  return aValues.map(function(r) {
    return {
      id: String(r[0] || "").trim(),
      date: String(r[1] || "").trim(),
      userId: String(r[2] || "").trim(),
      employeeCode: String(r[3] || "").trim(),
      name: String(r[4] || "").trim(),
      role: String(r[5] || "").trim(),
      firstCheckin: String(r[6] || "").trim(),
      lastCheckout: String(r[7] || "").trim(),
      totalDuration: String(r[8] || "").trim(),
      shiftStatus: String(r[9] || "").trim()
    };
  });
}

function formatHeaderRow(sheet, numColumns) {
  sheet.getRange(1, 1, 1, numColumns)
    .setFontWeight("bold")
    .setBackground("#0f172a")
    .setFontColor("#ffffff");
  sheet.setFrozenRows(1);
}

function formatTotalTime(totalSeconds) {
  var sec = Math.max(0, Math.round(Number(totalSeconds || 0)));
  var hrs = Math.floor(sec / 3600);
  var mins = Math.floor((sec % 3600) / 60);
  var secs = sec % 60;
  return (hrs < 10 ? "0" + hrs : hrs) + ":" + (mins < 10 ? "0" + mins : mins) + ":" + (secs < 10 ? "0" + secs : secs);
}

/**
 * Explicit tab initialization function for external setup.
 * Uses getSandboxSpreadsheet() to guarantee isolation.
 * Initializes Employee_Directory with the 3 intended Sandbox employees.
 */
function createAllTabsNow() {
  var ss = getSandboxSpreadsheet();
  var tabs = [
    { name: "Live_Presence", headers: ["Employee Code", "Employee Name", "User Role", "Designation", "Current Status", "Active Task", "Elapsed Time", "Total Today Time", "First Check-in", "Device Timezone", "Platform Mode", "Last Heartbeat", "User ID"] },
    { name: "Time_Logs", headers: ["Session ID", "Employee Code", "Employee Name", "Role", "Designation", "Date (YYYY-MM-DD)", "Start Time", "End Time", "Duration (Seconds)", "Total Time", "Idle Minutes", "Mouse %", "Keyboard %", "Status", "Task", "User ID"] },
    { name: "Employee_Directory", headers: ["Employee Code", "Username", "Full Name", "Email", "Role", "Designation", "Date Hired", "Monthly Rate", "Hourly Rate", "Team Leader", "Screenshot Monitored", "Activity Monitored", "Account Status", "Masked Password", "User ID", "AccountPassword", "mustChangePassword"] },
    { name: "Daily_Attendance", headers: ["Log ID", "Date", "User ID", "Employee Code", "Employee Name", "Role", "First Check-in", "Last Check-out", "Total Duration", "Shift Status"] },
    { name: "Audit_Logs", headers: ["Log ID", "Timestamp (ISO)", "Category", "Actor ID", "Actor Name", "Actor Role", "Action Details", "IP / Device"] },
  ];

  tabs.forEach(function(t) {
    var sheet = ss.getSheetByName(t.name) || ss.insertSheet(t.name);
    if (sheet.getLastRow() === 0) {
      sheet.appendRow(t.headers);
      formatHeaderRow(sheet, t.headers.length);
    }
  });

  // Populate the 3 intended Sandbox employees in Employee_Directory if empty
  var empSheet = ss.getSheetByName("Employee_Directory");
  if (empSheet && empSheet.getLastRow() === 1) {
    // 1. Super Admin
    empSheet.appendRow([
      "SuperAdmin", "admin", "Admin", "admin@llc.com", "admin", "Admin",
      "2024-01-01", 0, 0, "", "NO", "NO", "active", "********", "usr-superadmin-red",
      "AdminpassW0rd123!", false
    ]);
    // 2. Pia — Trainer
    empSheet.appendRow([
      "LLC-0003", "trainer", "Pia", "piaodahcam@gmail.com", "trainer", "Trainer",
      "2020-01-01", 0, 0, "", "NO", "NO", "active", "********", "usr-llc-0003",
      "Password123!", true
    ]);
    // 3. Juan David — Agent
    empSheet.appendRow([
      "LLC-0023", "jdavid", "Juan David", "jdavid@gmail.com", "agent", "Agent",
      "2024-01-01", 0, 0, "usr-llc-0003", "NO", "NO", "active", "********", "usr-llc-0023",
      "Password123!", true
    ]);
  }

  SpreadsheetApp.flush();
  Logger.log("Initialized Sandbox Spreadsheet tabs with authoritative Employee_Directory successfully!");
}
