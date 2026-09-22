export const DB_NAME = "vault1"

export const NOTE_ROLES = {
    VIEWER: "viewer",
    EDITOR: "editor",
    OWNER: "owner"
};

export const ROLE_HIERARCHY = {
    [NOTE_ROLES.VIEWER]: 1,
    [NOTE_ROLES.EDITOR]: 2,
    [NOTE_ROLES.OWNER]: 3
};

export const NOTE_PERMISSIONS = {
    [NOTE_ROLES.VIEWER]: ["notes:read"],
    [NOTE_ROLES.EDITOR]: ["notes:read", "notes:write"],
    [NOTE_ROLES.OWNER]: [
        "notes:read",
        "notes:write",
        "notes:delete",
        "notes:share",
        "notes:manage_access"
    ]
};


export const USER_ROLES = {
    USER: "user",
    ADMIN: "admin"
};