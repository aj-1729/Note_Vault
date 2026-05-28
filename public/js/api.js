// public/js/api.js
const BACKEND_URL = "http://localhost:8000/api/v1";

export const API = {
    // --- AUTH ACTIONS ---

    async register(username, email, password) {
        const response = await fetch(`${BACKEND_URL}/users/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password })
        });
        return await response.json();
    },
    async login(email, password) {
        const response = await fetch(`${BACKEND_URL}/users/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
            credentials: "include" // Mandatory to send/receive HttpOnly cookies
        });
        return await response.json();
    },

    async logout() {
        const response = await fetch(`${BACKEND_URL}/users/logout`, {
            method: "GET",
            credentials: "include"
        });
        return await response.json();
    },

    // --- SECURE NOTE ACTIONS ---
    async createNote(title, encryptedContent, tags) {
        const response = await fetch(`${BACKEND_URL}/notes/create`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title, content: encryptedContent, tags }),
            credentials: "include"
        });
        return await response.json();
    },

    async getAllNotes() {
        const response = await fetch(`${BACKEND_URL}/notes/all`, {
            method: "GET",
            credentials: "include"
        });
        return await response.json();
    },

    async updateNote(noteId, title, encryptedContent, tags) {
        const response = await fetch(`${BACKEND_URL}/notes/update/${noteId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ title, content: encryptedContent, tags }),
            credentials: "include"
        });
        return await response.json();
    },

    async deleteNote(noteId) {
        const response = await fetch(`${BACKEND_URL}/notes/delete/${noteId}`, {
            method: "DELETE",
            credentials: "include"
        });
        return await response.json();
    }
};