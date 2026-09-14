/**
 * Phish-Guard - Authentication & Developer RBAC Engine (auth.js)
 * -------------------------------------------------------------
 * Provides Role-Based Access Control (RBAC):
 * - User Role: Standard Security Analyst / Trainee
 * - Developer Role: Platform Engineer & Detection Rule Authority (Privileged Access)
 *
 * Capabilities:
 * - User Login / Registration / Session Management
 * - Developer Console Gateway with Cryptographic Access Control
 * - Live Detection & Heuristic Regex Rule Engine Manager
 * - Global Domain / TLD Blacklist & Threat Feed Engine
 * - AI Heuristic Sensitivity & Risk Weights Tuning
 * - RBAC Security Audit & Telemetry Logger
 */

(function () {
    'use strict';

    // ================================================================
    //  STORAGE KEYS & DEFAULT SEED DATA
    // ================================================================
    const STORAGE_KEY_USER      = 'phishguard_auth_user';
    const STORAGE_KEY_USERS_DB  = 'phishguard_registered_users';
    const STORAGE_KEY_RULES     = 'phishguard_detection_rules';
    const STORAGE_KEY_BLACKLIST = 'phishguard_domain_blacklist';
    const STORAGE_KEY_CONFIG    = 'phishguard_engine_config';
    const STORAGE_KEY_AUDIT     = 'phishguard_audit_logs';

    // Default Seed Accounts
    const DEFAULT_ACCOUNTS = [
        {
            id: 'usr-analyst-01',
            email: 'analyst@defense.local',
            passwordHash: 'analyst123',
            name: 'Security Analyst Alex',
            role: 'user',
            organization: 'Enterprise SOC Blue Team',
            createdAt: '2026-09-01T08:00:00.000Z'
        },
        {
            id: 'dev-root-01',
            email: 'dhruv@phishguard.dev',
            passwordHash: 'admin123',
            name: 'Dhruv Upadhyay (Lead Dev)',
            role: 'developer',
            organization: 'Phish-Guard Core Engineering',
            createdAt: '2026-09-01T00:00:00.000Z'
        },
        {
            id: 'dev-root-02',
            email: 'dev@phishguard.io',
            passwordHash: 'devroot2026',
            name: 'Platform Developer Console',
            role: 'developer',
            organization: 'Threat Research Labs',
            createdAt: '2026-09-01T00:00:00.000Z'
        }
    ];

    // Default Detection Rules (editable by Developers)
    const DEFAULT_RULES = [
        {
            id: 'rule-001',
            name: 'Urgent Wire / Banking Pressure Scam',
            category: 'Financial / BEC',
            pattern: '\\b(wire transfer|bank account suspended|unauthorized debit|reversal failed|funds locked|swift code)\\b',
            flags: 'i',
            weight: 35,
            severity: 'high',
            isActive: true,
            description: 'Flags urgent demands for wire transfers or claims of locked financial accounts.',
            createdBy: 'Dhruv (Developer)'
        },
        {
            id: 'rule-002',
            name: 'Corporate SSO / M365 Credential Harvest',
            category: 'Credential Harvester',
            pattern: '\\b(microsoftonline|password expires? (today|within \\d+ hours?)|sso-login|verify credentials?|re-authenticate)\\b',
            flags: 'i',
            weight: 40,
            severity: 'critical',
            isActive: true,
            description: 'Identifies fake corporate Single Sign-On and password expiration lures.',
            createdBy: 'Dhruv (Developer)'
        },
        {
            id: 'rule-003',
            name: 'Executive Whaling / Gift Card Solicitation',
            category: 'Executive BEC',
            pattern: '\\b(gift cards?|apple card|itunes|steam card|scratch the (back|security film)|confidential task|cannot take calls)\\b',
            flags: 'i',
            weight: 45,
            severity: 'critical',
            isActive: true,
            description: 'Detects untraceable gift card purchase demands common in CEO fraud.',
            createdBy: 'Dhruv (Developer)'
        }
    ];