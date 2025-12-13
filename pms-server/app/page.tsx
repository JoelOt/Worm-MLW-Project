import React from 'react';

export default function BSM_Barcelona_Portal() {
    // Real BSM parking locations in Barcelona
    const locations = [
        { id: 'bsm-boqueria', name: 'BSM Boqueria Market' },
        { id: 'bsm-nord', name: 'BSM Barcelona Nord Station' },
        { id: 'bsm-gracia', name: 'BSM Torrent de l\'Olla' },
        { id: 'bsm-glories', name: 'BSM Plaça de les Arts' },
        { id: 'bsm-litoral', name: 'BSM Litoral Port' },
    ];

    return (
        <div style={styles.container}>
            {/* Header - Public View (Not Logged In) */}
            <header style={styles.header}>
                <div style={styles.logoSection}>
                    {/* Mimicking the BSM Logo style */}
                    <div style={styles.bsmLogo}>
                        <span style={styles.bsmLogoText}>B(D)SM</span>
                    </div>
                    <div style={styles.headerTitle}>
                        <span style={styles.headerMain}>Barcelona</span>
                        <span style={styles.headerSub}>Parking Services</span>
                    </div>
                </div>
                <nav style={styles.nav}>
                    <a href="#" style={styles.navLink}>Map</a>
                    <a href="#" style={styles.navLink}>Subscriptions</a>
                    <a href="#" style={styles.navLink}>Business</a>
                    <button style={styles.loginButton}>User Login</button>
                    <span style={styles.langSelector}>EN | ES | CA</span>
                </nav>
            </header>

            {/* Hero Section with Booking Widget */}
            <main style={styles.main}>
                <div style={styles.heroContent}>
                    <h1 style={styles.heroTitle}>Park in Barcelona</h1>
                    <p style={styles.heroSubtitle}>
                        Over 40 car parks connected to you. Book your spot now.
                    </p>

                    {/* THE VULNERABLE FORM 
             This resembles the "Reserve Now" widget on the homepage.
             Submitting this triggers the POST request that carries the exploit payload.
          */}
                    <div style={styles.widgetCard}>
                        <div style={styles.widgetHeader}>
                            <span style={styles.widgetTabActive}>Daily / Hourly</span>
                            <span style={styles.widgetTab}>Subscriptions</span>
                        </div>

                        <form action="/api/parking/search" method="POST" style={styles.form}>

                            <div style={styles.inputGroup}>
                                <label style={styles.label} htmlFor="location">Where do you want to park?</label>
                                <select id="location" name="location" style={styles.select} defaultValue="">
                                    <option value="" disabled>Select a car park...</option>
                                    {locations.map(loc => (
                                        <option key={loc.id} value={loc.id}>{loc.name}</option>
                                    ))}
                                </select>
                            </div>

                            <div style={styles.row}>
                                <div style={styles.halfInputGroup}>
                                    <label style={styles.label} htmlFor="entry">Entry</label>
                                    <input type="datetime-local" id="entry" name="entryDate" style={styles.input} />
                                </div>
                                <div style={styles.halfInputGroup}>
                                    <label style={styles.label} htmlFor="exit">Exit</label>
                                    <input type="datetime-local" id="exit" name="exitDate" style={styles.input} />
                                </div>
                            </div>

                            <div style={styles.inputGroup}>
                                <label style={styles.label} htmlFor="plate">License Plate (Optional)</label>
                                <input type="text" id="plate" name="licensePlate" placeholder="e.g., 1234 ABC" style={styles.input} />
                            </div>

                            <button type="submit" style={styles.submitButton}>
                                SEARCH PARKING
                            </button>
                        </form>
                    </div>
                </div>
            </main>

            {/* Footer / Disclaimer */}
            <footer style={styles.footer}>
                <div style={styles.footerLinks}>
                    <span>Legal Notice</span>
                    <span>Privacy Policy</span>
                    <span>Cookies</span>
                </div>
                <div style={styles.securityWarning}>
                    🛑 <strong>RESEARCH ENVIRONMENT</strong> 🛑<br />
                    Vulnerable Instance: Next.js 16.0.6 | React 19.2.0<br />
                    (CVE-2025-55182 / CVE-2025-66478 Target)
                </div>
            </footer>
        </div>
    );
}

// Styles adapted to match BSM's Clean Red/White/Grey aesthetic
// Fixed overflow issues by adding boxSizing: border-box
const styles: Record<string, React.CSSProperties> = {
    container: {
        fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif',
        backgroundColor: '#f4f4f4',
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        margin: 0,
        padding: 0,
    },
    header: {
        backgroundColor: '#ffffff',
        borderBottom: '4px solid #E30613', // BSM Red
        padding: '0.8rem 2rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        boxShadow: '0 2px 5px rgba(0,0,0,0.05)',
    },
    logoSection: {
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
    },
    bsmLogo: {
        backgroundColor: '#E30613', // BSM Red
        color: 'white',
        padding: '0.5rem 0.8rem',
        fontWeight: '900',
        fontSize: '1.5rem',
        letterSpacing: '1px',
        borderRadius: '2px',
    },
    bsmLogoText: {
        fontFamily: 'Arial Black, sans-serif',
    },
    headerTitle: {
        display: 'flex',
        flexDirection: 'column',
        lineHeight: '1.1',
        color: '#333',
    },
    headerMain: {
        fontWeight: 'bold',
        fontSize: '1.2rem',
        textTransform: 'uppercase',
    },
    headerSub: {
        fontSize: '0.9rem',
        color: '#666',
    },
    nav: {
        display: 'flex',
        alignItems: 'center',
        gap: '1.5rem',
    },
    navLink: {
        textDecoration: 'none',
        color: '#333',
        fontWeight: '500',
        fontSize: '0.95rem',
    },
    loginButton: {
        backgroundColor: '#333',
        color: 'white',
        border: 'none',
        padding: '0.6rem 1.2rem',
        borderRadius: '4px',
        cursor: 'pointer',
        fontWeight: 'bold',
        fontSize: '0.9rem',
    },
    langSelector: {
        fontSize: '0.8rem',
        color: '#888',
        fontWeight: '600',
        cursor: 'pointer',
    },
    main: {
        flex: 1,
        backgroundImage: 'linear-gradient(rgba(0,0,0,0.5), rgba(0,0,0,0.5)), url("https://images.unsplash.com/photo-1554672408-688544e3e57f?auto=format&fit=crop&q=80")',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '2rem',
    },
    heroContent: {
        width: '100%',
        maxWidth: '1000px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
    },
    heroTitle: {
        color: 'white',
        fontSize: '3rem',
        fontWeight: 'bold',
        marginBottom: '0.5rem',
        textShadow: '0 2px 4px rgba(0,0,0,0.5)',
        textAlign: 'center',
    },
    heroSubtitle: {
        color: '#f0f0f0',
        fontSize: '1.2rem',
        marginBottom: '2.5rem',
        textShadow: '0 1px 3px rgba(0,0,0,0.5)',
        textAlign: 'center',
    },
    widgetCard: {
        backgroundColor: 'white',
        borderRadius: '8px',
        boxShadow: '0 15px 30px rgba(0,0,0,0.2)',
        width: '100%',
        maxWidth: '450px',
        overflow: 'hidden',
    },
    widgetHeader: {
        display: 'flex',
        borderBottom: '1px solid #eee',
    },
    widgetTabActive: {
        flex: 1,
        padding: '1rem',
        textAlign: 'center',
        backgroundColor: 'white',
        fontWeight: 'bold',
        color: '#E30613',
        borderTop: '3px solid #E30613',
        cursor: 'pointer',
    },
    widgetTab: {
        flex: 1,
        padding: '1rem',
        textAlign: 'center',
        backgroundColor: '#f9f9f9',
        color: '#666',
        borderTop: '3px solid transparent',
        cursor: 'pointer',
    },
    form: {
        padding: '2rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.2rem',
        boxSizing: 'border-box', // Ensure padding doesn't expand width
    },
    inputGroup: {
        display: 'flex',
        flexDirection: 'column',
        gap: '0.4rem',
        width: '100%', // Explicit width
    },
    row: {
        display: 'flex',
        gap: '1rem',
        width: '100%', // Explicit width
    },
    halfInputGroup: {
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        gap: '0.4rem',
        minWidth: 0, // Prevents flex item overflow
    },
    label: {
        fontWeight: 'bold',
        color: '#444',
        fontSize: '0.85rem',
        textTransform: 'uppercase',
    },
    input: {
        padding: '0.8rem',
        borderRadius: '4px',
        border: '1px solid #ccc',
        fontSize: '1rem',
        backgroundColor: '#fff',
        width: '100%',        // Force full width of container
        boxSizing: 'border-box', // Crucial: Includes padding/border in width calculation
    },
    select: {
        padding: '0.8rem',
        borderRadius: '4px',
        border: '1px solid #ccc',
        fontSize: '1rem',
        backgroundColor: '#fff',
        width: '100%',        // Force full width of container
        boxSizing: 'border-box', // Crucial: Includes padding/border in width calculation
    },
    submitButton: {
        marginTop: '0.5rem',
        padding: '1rem',
        backgroundColor: '#E30613', // BSM Red
        color: 'white',
        border: 'none',
        borderRadius: '4px',
        fontSize: '1.1rem',
        fontWeight: 'bold',
        cursor: 'pointer',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
        transition: 'background 0.2s',
        width: '100%', // Full width button
    },
    footer: {
        backgroundColor: '#333',
        color: '#ccc',
        padding: '2rem',
        textAlign: 'center',
        fontSize: '0.9rem',
    },
    footerLinks: {
        display: 'flex',
        justifyContent: 'center',
        gap: '2rem',
        marginBottom: '1.5rem',
        fontWeight: '500',
    },
    securityWarning: {
        display: 'inline-block',
        border: '1px dashed #E30613',
        padding: '0.5rem 1rem',
        color: '#E30613',
        backgroundColor: '#1a1a1a',
        borderRadius: '4px',
        fontSize: '0.8rem',
    }
};