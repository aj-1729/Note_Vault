// public/js/app.js
import { API } from "./api.js";
import { encryptNote, decryptNote } from "./utils/cryptoUtils.js";

// Global Volatile State (Never saved to localStorage)
const AppState = {
    userEmail: null,
    masterPassword: null,
    activeNotes: [],
    currentOpenNoteId: null 
};

// --- DOM ELEMENTS ---
const authView = document.getElementById('auth-view');
const dashboardView = document.getElementById('dashboard-view');
const loginForm = document.getElementById('login-form');
const authMessage = document.getElementById('auth-message');
const notesListEl = document.getElementById('notes-list');
const editorContainer = document.getElementById('editor-container');
const emptyState = document.getElementById('empty-state');
const editorMessage = document.getElementById('editor-message');

const titleInput = document.getElementById('note-title');
const tagsInput = document.getElementById('note-tags');
const contentInput = document.getElementById('note-content');

// --- EVENT LISTENERS ---

// 1. Handle Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    authMessage.textContent = "Unlocking vault...";
    
    try {
        const res = await API.login(email, password);
        if (!res.success) throw new Error(res.message);

        // Store keys securely in JS memory for this session
        AppState.userEmail = email;
        AppState.masterPassword = password;
        
        // Switch Views
        authView.classList.remove('active');
        dashboardView.classList.add('active');
        
        await loadDashboard();
    } catch (err) {
        authMessage.textContent = err.message;
        authMessage.style.color = "var(--danger)";
    }
});

// 2. Handle Logout
document.getElementById('btn-logout').addEventListener('click', async () => {
    await API.logout();
    // Wipe memory
    AppState.userEmail = null;
    AppState.masterPassword = null;
    AppState.activeNotes = [];
    AppState.currentOpenNoteId = null;
    
    // Switch views
    dashboardView.classList.remove('active');
    authView.classList.add('active');
    loginForm.reset();
    authMessage.textContent = "Vault locked.";
});

// 3. Setup New Note UI
document.getElementById('btn-new-note').addEventListener('click', () => {
    AppState.currentOpenNoteId = null;
    titleInput.value = '';
    tagsInput.value = '';
    contentInput.value = '';
    
    emptyState.classList.add('hidden');
    editorContainer.classList.remove('hidden');
    document.getElementById('btn-delete-note').classList.add('hidden'); // Can't delete a new note
    editorMessage.textContent = '';
});

// 4. Save/Update Note
document.getElementById('btn-save-note').addEventListener('click', async () => {
    const title = titleInput.value;
    const content = contentInput.value;
    const tags = tagsInput.value.split(',').map(t => t.trim()).filter(t => t); // clean tags
    
    if (!title || !content) {
        editorMessage.textContent = "Title and content are required.";
        return;
    }

    editorMessage.textContent = "Encrypting and saving...";
    
    try {
        // ZERO-KNOWLEDGE ENCRYPTION: Scramble before network transmission!
        const cipherPayload = await encryptNote(content, AppState.masterPassword, AppState.userEmail);

        let res;
        if (AppState.currentOpenNoteId) {
            // Update existing Note Pointer
            res = await API.updateNote(AppState.currentOpenNoteId, title, cipherPayload, tags);
        } else {
            // Create New Note Pointer
            res = await API.createNote(title, cipherPayload, tags);
        }

        if (!res.success) throw new Error(res.message);
        
        editorMessage.textContent = "Saved securely!";
        editorMessage.style.color = "var(--accent)";
        await loadDashboard(); // Refresh sidebar
        
    } catch (err) {
        editorMessage.textContent = err.message;
        editorMessage.style.color = "var(--danger)";
    }
});

// 5. Delete Note
document.getElementById('btn-delete-note').addEventListener('click', async () => {
    if (!AppState.currentOpenNoteId) return;
    
    if(confirm("Are you sure you want to permanently delete this note?")) {
        try {
            await API.deleteNote(AppState.currentOpenNoteId);
            AppState.currentOpenNoteId = null;
            editorContainer.classList.add('hidden');
            emptyState.classList.remove('hidden');
            await loadDashboard();
        } catch (err) {
            alert("Failed to delete note.");
        }
    }
});


// --- CORE LOGIC FUNCTIONS ---

async function loadDashboard() {
    try {
        const res = await API.getAllNotes();
        if (!res.success) throw new Error(res.message);
        
        AppState.activeNotes = res.data.notes;
        renderNotesSidebar();
    } catch (err) {
        console.error("Failed to load notes", err);
    }
}

function renderNotesSidebar() {
    notesListEl.innerHTML = '';
    AppState.activeNotes.forEach(note => {
        const li = document.createElement('li');
        li.className = 'note-item';
        li.innerHTML = `
            <h4>${note.title}</h4>
            <small>${new Date(note.updatedAt).toLocaleDateString()}</small>
        `;
        
        // When clicking a note in the sidebar
        li.addEventListener('click', () => openNote(note));
        notesListEl.appendChild(li);
    });
}

async function openNote(noteData) {
    AppState.currentOpenNoteId = noteData._id;
    editorMessage.textContent = "Decrypting securely...";
    
    emptyState.classList.add('hidden');
    editorContainer.classList.remove('hidden');
    document.getElementById('btn-delete-note').classList.remove('hidden');

    titleInput.value = noteData.title;
    tagsInput.value = noteData.tags ? noteData.tags.join(', ') : "";
    contentInput.value = "Loading encrypted data...";

    try {
        // POINTER ARCHITECTURE: Fetch ciphertext from Cloudinary URL
        const cloudinaryUrl = noteData.content; 
        const fileResponse = await fetch(cloudinaryUrl);
        const cipherTextString = await fileResponse.text();

        // DECRYPTION: Unpack it directly in the browser!
        const plainText = await decryptNote(cipherTextString, AppState.masterPassword, AppState.userEmail);
        
        contentInput.value = plainText;
        editorMessage.textContent = "";
    } catch (err) {
        contentInput.value = "Error decrypting note.";
        editorMessage.textContent = "Decryption failed. Password mismatch or corrupted data.";
    }
}