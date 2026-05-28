// public/js/app.js
// Uses crypto.Utils.js for client-side AES-GCM encryption/decryption
import { API } from "./api.js";
import { encryptNote, decryptNote } from "./utils/crypto.Utils.js";

// ─── App State ───────────────────────────────────────────────────────────────
const State = {
    userEmail: null,
    masterPassword: null,
    userId: null,       // MongoDB _id — used as the socket room key
    notes: [],
    currentNoteId: null,
};
const socket = io("http://localhost:8000");

// Listen for the update ping from the server
socket.on("vault_updated", async () => {
    console.log("Vault changed on another device! Syncing instantly...");
    if (State.userEmail) {
        await loadNotes(); // Silently re-fetch the notes list in the background
    }
});
// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const authView = document.getElementById("auth-view");
const dashboardView = document.getElementById("dashboard-view");

// Auth tabs
const tabLogin = document.getElementById("tab-login");
const tabRegister = document.getElementById("tab-register");
const panelLogin = document.getElementById("panel-login");
const panelRegister = document.getElementById("panel-register");

// Login form
const loginForm = document.getElementById("login-form");
const loginEmail = document.getElementById("login-email");
const loginPassword = document.getElementById("login-password");
const loginMessage = document.getElementById("login-message");

// Register form
const registerForm = document.getElementById("register-form");
const regUsername = document.getElementById("reg-username");
const regEmail = document.getElementById("reg-email");
const regPassword = document.getElementById("reg-password");
const registerMessage = document.getElementById("register-message");

// Dashboard
const notesList = document.getElementById("notes-list");
const searchInput = document.getElementById("search-notes");
const userEmailDisplay = document.getElementById("user-email-display");
const emptyState = document.getElementById("empty-state");
const editorContainer = document.getElementById("editor-container");
const noteTitleInput = document.getElementById("note-title");
const noteTagsInput = document.getElementById("note-tags");
const noteContentInput = document.getElementById("note-content");
const editorMessage = document.getElementById("editor-message");
const btnNewNote = document.getElementById("btn-new-note");
const btnSaveNote = document.getElementById("btn-save-note");
const btnDeleteNote = document.getElementById("btn-delete-note");
const btnLogout = document.getElementById("btn-logout");

// ─── Helpers ──────────────────────────────────────────────────────────────────
function showMsg(el, text, type = "") {
    el.textContent = text;
    el.className = "form-message" + (type ? ` ${type}` : "");
}

function showEditorMsg(text, type = "") {
    editorMessage.textContent = text;
    editorMessage.className = "editor-message" + (type ? ` ${type}` : "");
}

function formatDate(iso) {
    return new Date(iso).toLocaleDateString("en-IN", {
        day: "numeric", month: "short", year: "numeric",
    });
}

function switchView(view) {
    if (view === "auth") {
        authView.classList.add("active");
        dashboardView.classList.remove("active");
    } else {
        authView.classList.remove("active");
        dashboardView.classList.add("active");
    }
}

// ─── Tab switching ────────────────────────────────────────────────────────────
tabLogin.addEventListener("click", () => {
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
    panelLogin.classList.add("active");
    panelRegister.classList.remove("active");
    tabLogin.setAttribute("aria-selected", "true");
    tabRegister.setAttribute("aria-selected", "false");
    loginMessage.textContent = "";
});

tabRegister.addEventListener("click", () => {
    tabRegister.classList.add("active");
    tabLogin.classList.remove("active");
    panelRegister.classList.add("active");
    panelLogin.classList.remove("active");
    tabRegister.setAttribute("aria-selected", "true");
    tabLogin.setAttribute("aria-selected", "false");
    registerMessage.textContent = "";
});

// ─── Login ────────────────────────────────────────────────────────────────────
loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = loginEmail.value.trim();
    const password = loginPassword.value;

    if (!email || !password) {
        showMsg(loginMessage, "Please fill in all fields.", "error");
        return;
    }

    showMsg(loginMessage, "Logging in…");
    try {
        const res = await API.login(email, password);
        if (!res.success) throw new Error(res.message || "Login failed.");

        State.userEmail = email;
        State.masterPassword = password;
        // The backend room is keyed by MongoDB _id, not email
        State.userId = res.data?.user?._id;
        socket.emit("join_vault", State.userId);

        // Persist session so page refresh doesn't log out
        sessionStorage.setItem("vault_session", JSON.stringify({
            email,
            password,
            userId: State.userId
        }));

        switchView("dashboard");
        userEmailDisplay.textContent = email;
        await loadNotes();
    } catch (err) {
        showMsg(loginMessage, err.message, "error");
    }
});

// ─── Register ────────────────────────────────────────────────────────────────
registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = regUsername.value.trim();
    const email = regEmail.value.trim();
    const password = regPassword.value;

    if (!username || !email || !password) {
        showMsg(registerMessage, "All fields are required.", "error");
        return;
    }

    showMsg(registerMessage, "Creating account…");
    try {
        const res = await API.register(username, email, password);
        if (!res.success) throw new Error(res.message || "Registration failed.");

        showMsg(
            registerMessage,
            "Account created! Check the server terminal for your verification link, then log in.",
            "success"
        );
        registerForm.reset();
    } catch (err) {
        showMsg(registerMessage, err.message, "error");
    }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
btnLogout.addEventListener("click", async () => {
    await API.logout().catch(() => { });
    sessionStorage.removeItem("vault_session"); // Clear persisted session
    State.userEmail = null;
    State.masterPassword = null;
    State.userId = null;
    State.notes = [];
    State.currentNoteId = null;

    notesList.innerHTML = "";
    loginForm.reset();
    loginMessage.textContent = "";
    showEditorTab(false);

    switchView("auth");
});

// ─── New Note ─────────────────────────────────────────────────────────────────
btnNewNote.addEventListener("click", () => {
    State.currentNoteId = null;
    noteTitleInput.value = "";
    noteTagsInput.value = "";
    noteContentInput.value = "";
    showEditorTab(true);
    btnDeleteNote.classList.add("hidden");
    showEditorMsg("");
    setActiveNoteItem(null);
    noteTitleInput.focus();
});

// ─── Save Note ────────────────────────────────────────────────────────────────
btnSaveNote.addEventListener("click", async () => {
    const title = noteTitleInput.value.trim();
    const content = noteContentInput.value;
    const tags = noteTagsInput.value.split(",").map(t => t.trim()).filter(Boolean);

    if (!title) {
        showEditorMsg("Title is required.", "error");
        return;
    }
    if (!content) {
        showEditorMsg("Content cannot be empty.", "error");
        return;
    }

    showEditorMsg("Encrypting and saving…");
    btnSaveNote.disabled = true;

    try {
        // Encrypt content client-side before sending to server
        const cipherPayload = await encryptNote(content, State.masterPassword, State.userEmail);

        let res;
        if (State.currentNoteId) {
            res = await API.updateNote(State.currentNoteId, title, cipherPayload, tags);
        } else {
            res = await API.createNote(title, cipherPayload, tags);
        }

        if (!res.success) throw new Error(res.message || "Save failed.");

        // If new note, grab its id
        if (!State.currentNoteId && res.data?.note?._id) {
            State.currentNoteId = res.data.note._id;
        }

        showEditorMsg("Saved.", "success");
        btnDeleteNote.classList.remove("hidden");
        await loadNotes();
    } catch (err) {
        showEditorMsg(err.message, "error");
    } finally {
        btnSaveNote.disabled = false;
    }
});

// ─── Delete Note ─────────────────────────────────────────────────────────────
btnDeleteNote.addEventListener("click", async () => {
    if (!State.currentNoteId) return;
    if (!confirm("Delete this note permanently?")) return;

    try {
        const res = await API.deleteNote(State.currentNoteId);
        if (!res.success) throw new Error(res.message || "Delete failed.");

        State.currentNoteId = null;
        showEditorTab(false);
        await loadNotes();
    } catch (err) {
        showEditorMsg(err.message, "error");
    }
});

// ─── Search ───────────────────────────────────────────────────────────────────
searchInput.addEventListener("input", () => {
    const query = searchInput.value.toLowerCase();
    renderNotesList(
        State.notes.filter(n => n.title.toLowerCase().includes(query))
    );
});

// ─── Load / Render Notes ─────────────────────────────────────────────────────
async function loadNotes() {
    try {
        const res = await API.getAllNotes();
        if (!res.success) throw new Error(res.message || "Could not fetch notes.");
        State.notes = res.data?.note || [];
        renderNotesList(State.notes);
    } catch (err) {
        console.error("loadNotes error:", err);
    }
}

// ─── Auto-restore session on page refresh ────────────────────────────────────
// sessionStorage survives refresh but clears when the browser tab is closed.
// The HttpOnly cookie is still sent automatically, so we just re-hydrate state.
async function tryRestoreSession() {
    const saved = sessionStorage.getItem("vault_session");
    if (!saved) return;

    try {
        const { email, password, userId } = JSON.parse(saved);

        // Validate the cookie is still alive by hitting a protected endpoint
        const res = await API.getAllNotes();
        if (!res.success) throw new Error("Session expired");

        // Hydrate state
        State.userEmail = email;
        State.masterPassword = password;
        State.userId = userId;
        State.notes = res.data?.note || [];

        socket.emit("join_vault", userId);
        userEmailDisplay.textContent = email;
        switchView("dashboard");
        renderNotesList(State.notes);
    } catch {
        // Cookie expired or invalid — clear stale session and stay on login
        sessionStorage.removeItem("vault_session");
    }
}

// Run on every page load
tryRestoreSession();

function renderNotesList(notes) {
    notesList.innerHTML = "";
    if (!notes.length) {
        const li = document.createElement("li");
        li.className = "notes-empty";
        li.textContent = "No notes yet.";
        notesList.appendChild(li);
        return;
    }
    notes.forEach(note => {
        const li = document.createElement("li");
        li.className = "note-item" + (note._id === State.currentNoteId ? " active" : "");
        li.setAttribute("role", "listitem");
        li.dataset.id = note._id;
        li.innerHTML = `
            <div class="note-item-title">${escapeHtml(note.title)}</div>
            <div class="note-item-date">${formatDate(note.updatedAt)}</div>
        `;
        li.addEventListener("click", () => openNote(note));
        notesList.appendChild(li);
    });
}

function setActiveNoteItem(id) {
    document.querySelectorAll(".note-item").forEach(el => {
        el.classList.toggle("active", el.dataset.id === id);
    });
}

// ─── Open / Decrypt Note ──────────────────────────────────────────────────────
async function openNote(noteData) {
    State.currentNoteId = noteData._id;
    noteTitleInput.value = noteData.title;
    noteTagsInput.value = noteData.tags ? noteData.tags.join(", ") : "";
    noteContentInput.value = "";
    showEditorTab(true);
    btnDeleteNote.classList.remove("hidden");
    showEditorMsg("Decrypting…");
    setActiveNoteItem(noteData._id);

    try {
        // The content field is a Cloudinary URL pointing to the encrypted text file
        const fileResp = await fetch(noteData.content);
        if (!fileResp.ok) throw new Error("Could not retrieve note file.");
        const cipherText = await fileResp.text();
        const plainText = await decryptNote(cipherText, State.masterPassword, State.userEmail);
        noteContentInput.value = plainText;
        showEditorMsg("");
    } catch (err) {
        noteContentInput.value = "";
        showEditorMsg("Decryption failed — wrong password or corrupted note.", "error");
    }
}

// ─── Editor visibility ────────────────────────────────────────────────────────
function showEditorTab(show) {
    if (show) {
        editorContainer.classList.remove("hidden");
        emptyState.style.display = "none";
    } else {
        editorContainer.classList.add("hidden");
        emptyState.style.display = "";
    }
}

// ─── Escape HTML ─────────────────────────────────────────────────────────────
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}