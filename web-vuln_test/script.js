// CODEXIO Vulnerability Scanner - Enhanced Frontend JavaScript

// Global variables
let scanData = null;
let isGeneratingPDF = false;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('CODEXIO Vulnerability Scanner initialized');
    
    // Add animation classes to main elements
    addAnimations();
    
    // Check if we have scan results in PHP
    const vulnArea = document.getElementById('vulnArea');
    if (vulnArea && vulnArea.querySelector('.vulnerability-list')) {
        scanData = extractScanData();
        addAnimationToResults();
    }
    
    // Add event listeners for better UX
    addEventListeners();
});

// Add smooth animations to page elements
function addAnimations() {
    const elements = document.querySelectorAll('.process-area, .vuln-area, .form-control, .btn');
    elements.forEach((element, index) => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            element.style.transition = 'all 0.6s ease';
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }, index * 100);
    });
}

// Add animations to scan results
function addAnimationToResults() {
    const vulnItems = document.querySelectorAll('.vuln-item');
    vulnItems.forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = 'translateX(30px)';
        
        setTimeout(() => {
            item.style.transition = 'all 0.5s ease';
            item.style.opacity = '1';
            item.style.transform = 'translateX(0)';
        }, index * 150);
    });
}

// Add event listeners for better user experience
function addEventListeners() {
    // Form submission feedback
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', function() {
            const scanBtn = this.querySelector('button[name="scan"]');
            if (scanBtn) {
                scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning...';
                scanBtn.disabled = true;
            }
        });
    }
    
    // Input field enhancements
    const targetInput = document.querySelector('input[name="target"]');
    if (targetInput) {
        targetInput.addEventListener('input', function() {
            if (this.value.trim()) {
                this.classList.add('is-valid');
                this.classList.remove('is-invalid');
            } else {
                this.classList.remove('is-valid');
            }
        });
        
        targetInput.addEventListener('blur', function() {
            if (!this.value.trim()) {
                this.classList.add('is-invalid');
            }
        });
    }
}

// Extract scan data from the DOM with enhanced parsing
function extractScanData() {
    const vulnArea = document.getElementById('vulnArea');
    const processArea = document.getElementById('processArea');
    
    if (!vulnArea || !processArea) return null;
    
    const vulnerabilities = [];
    const vulnItems = vulnArea.querySelectorAll('.vuln-item');
    
    vulnItems.forEach((item, index) => {
        const vuln = {
            type: extractTextContent(item.querySelector('h6'), 'Unknown'),
            url: extractTextContent(item.querySelector('p:nth-child(2)'), 'Unknown').replace('URL: ', ''),
            description: extractTextContent(item.querySelector('p:nth-child(3)'), 'Unknown').replace('Description: ', ''),
            details: extractTextContent(item.querySelector('p:nth-child(4)'), 'No details').replace('Details: ', ''),
            ai_analysis: extractTextContent(item.querySelector('.ai-content'), 'No AI analysis')
        };
        vulnerabilities.push(vuln);
    });
    
    // Extract scan summary with better parsing
    const scanSummary = {};
    const summaryItems = processArea.querySelectorAll('.scan-summary li');
    summaryItems.forEach(item => {
        const text = item.textContent.trim();
        if (text.includes('Target:')) scanSummary.target = text.replace('Target:', '').trim();
        if (text.includes('Timestamp:')) scanSummary.timestamp = text.replace('Timestamp:', '').trim();
        if (text.includes('Scan Level:')) scanSummary.scan_level = text.replace('Scan Level:', '').trim();
        if (text.includes('Total Issues:')) scanSummary.total_issues = text.replace('Total Issues:', '').trim();
        if (text.includes('Vulnerabilities:')) scanSummary.vulnerabilities = text.replace('Vulnerabilities:', '').trim();
    });
    
    return {
        summary: scanSummary,
        vulnerabilities: vulnerabilities
    };
}

// Helper function to safely extract text content
function extractTextContent(element, defaultValue = '') {
    if (!element) return defaultValue;
    return element.textContent?.trim() || defaultValue;
}

// Enhanced PDF generation with better error handling and progress feedback
async function generatePDF() {
    if (isGeneratingPDF) {
        showNotification('PDF generation already in progress...', 'warning');
        return;
    }
    
    try {
        isGeneratingPDF = true;
        console.log('Generating PDF report...');
        
        // Show loading state
        const printBtn = document.querySelector('.print-btn');
        const originalText = printBtn.innerHTML;
        printBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Generating PDF...';
        printBtn.disabled = true;
        
        // Validate scan data
        if (!scanData || !scanData.vulnerabilities || scanData.vulnerabilities.length === 0) {
            throw new Error('No scan data available for PDF generation');
        }
        
        // Create PDF document with enhanced styling
        const { jsPDF } = window.jspdf;
        if (!jsPDF) {
            throw new Error('jsPDF library not loaded');
        }
        
        const doc = new jsPDF('p', 'mm', 'a4');
        
        // Set document properties
        doc.setProperties({
            title: 'CODEXIO Vulnerability Scan Report',
            subject: 'Web Application Security Assessment',
            author: 'CODEXIO Scanner',
            creator: 'CODEXIO Vulnerability Scanner',
            keywords: 'security, vulnerability, scan, report, web application'
        });
        
        // Add enhanced header with logo placeholder
        addPDFHeader(doc);
        
        // Add scan summary
        addScanSummary(doc);
        
        // Add vulnerability details
        addVulnerabilityDetails(doc);
        
        // Add footer with page numbers
        addPDFFooter(doc);
        
        // Save the PDF with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const filename = `codexio-vulnerability-report-${timestamp}.pdf`;
        doc.save(filename);
        
        console.log('PDF generated successfully:', filename);
        
        // Show success message
        showNotification('PDF report generated successfully!', 'success');
        
        // Add download animation
        animateDownloadSuccess();
        
    } catch (error) {
        console.error('Error generating PDF:', error);
        showNotification(`Error generating PDF: ${error.message}`, 'error');
    } finally {
        // Restore button state
        const printBtn = document.querySelector('.print-btn');
        if (printBtn) {
            printBtn.innerHTML = '📄 Generate PDF Report';
            printBtn.disabled = false;
        }
        isGeneratingPDF = false;
    }
}

// Add enhanced PDF header
function addPDFHeader(doc) {
    // Title
    doc.setFontSize(24);
    doc.setTextColor(44, 62, 80);
    doc.text('CODEXIO', 105, 25, { align: 'center' });
    
    // Subtitle
    doc.setFontSize(16);
    doc.setTextColor(52, 73, 94);
    doc.text('Vulnerability Scan Report', 105, 35, { align: 'center' });
    
    // Decorative line
    doc.setDrawColor(52, 152, 219);
    doc.setLineWidth(0.5);
    doc.line(20, 40, 190, 40);
    
    // Date
    doc.setFontSize(10);
    doc.setTextColor(128, 128, 128);
    doc.text(`Generated: ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}`, 105, 50, { align: 'center' });
}

// Add scan summary to PDF
function addScanSummary(doc) {
    doc.setFontSize(14);
    doc.setTextColor(44, 62, 80);
    doc.text('Scan Summary', 20, 65);
    
    if (scanData && scanData.summary) {
        let yPos = 75;
        Object.entries(scanData.summary).forEach(([key, value]) => {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            doc.setFontSize(10);
            doc.setTextColor(52, 73, 94);
            doc.text(`${label}:`, 25, yPos);
            doc.setTextColor(44, 62, 80);
            doc.text(value, 70, yPos);
            yPos += 7;
        });
    }
}

// Add vulnerability details to PDF
function addVulnerabilityDetails(doc) {
    if (scanData && scanData.vulnerabilities.length > 0) {
        doc.addPage();
        doc.setFontSize(16);
        doc.setTextColor(231, 76, 60);
        doc.text('Vulnerability Details', 20, 20);
        
        let yPos = 35;
        let pageCount = 1;
        
        scanData.vulnerabilities.forEach((vuln, index) => {
            // Check if we need a new page
            if (yPos > 250) {
                doc.addPage();
                pageCount++;
                yPos = 20;
            }
            
            // Vulnerability header
            doc.setFontSize(12);
            doc.setTextColor(231, 76, 60);
            doc.text(`${index + 1}. ${vuln.type}`, 20, yPos);
            yPos += 7;
            
            // Vulnerability details
            doc.setFontSize(10);
            doc.setTextColor(44, 62, 80);
            
            // URL
            doc.text('URL:', 25, yPos);
            const urlText = doc.splitTextToSize(vuln.url, 150);
            doc.text(urlText, 70, yPos);
            yPos += (urlText.length * 4);
            
            // Description
            doc.text('Description:', 25, yPos);
            const descText = doc.splitTextToSize(vuln.description, 150);
            doc.text(descText, 70, yPos);
            yPos += (descText.length * 4);
            
            // Details
            doc.text('Details:', 25, yPos);
            const detailsText = doc.splitTextToSize(vuln.details, 150);
            doc.text(detailsText, 70, yPos);
            yPos += (detailsText.length * 4);
            
            // AI Analysis
            if (vuln.ai_analysis && vuln.ai_analysis !== 'No AI analysis') {
                doc.setTextColor(52, 152, 219);
                doc.text('AI Analysis & Solutions:', 25, yPos);
                yPos += 5;
                
                doc.setTextColor(44, 62, 80);
                const aiText = doc.splitTextToSize(vuln.ai_analysis, 150);
                doc.text(aiText, 30, yPos);
                yPos += (aiText.length * 4);
            }
            
            yPos += 10;
        });
    }
}

// Add PDF footer
function addPDFFooter(doc) {
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(128, 128, 128);
        doc.text(`Page ${i} of ${pageCount}`, 105, 290, { align: 'center' });
        doc.text(`Generated by CODEXIO Scanner`, 105, 295, { align: 'center' });
    }
}

// Animate download success
function animateDownloadSuccess() {
    const printBtn = document.querySelector('.print-btn');
    if (printBtn) {
        printBtn.classList.add('btn-success');
        printBtn.innerHTML = '✅ PDF Generated!';
        
        setTimeout(() => {
            printBtn.classList.remove('btn-success');
            printBtn.innerHTML = '📄 Generate PDF Report';
        }, 3000);
    }
}

// Enhanced notification system
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.alert');
    existingNotifications.forEach(notification => notification.remove());
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px; max-width: 400px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);';
    
    // Add icon based on type
    const icons = {
        'success': '✅',
        'error': '❌',
        'warning': '⚠️',
        'info': 'ℹ️'
    };
    
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <span class="me-2">${icons[type] || icons.info}</span>
            <span>${message}</span>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Add to page with animation
    document.body.appendChild(notification);
    notification.style.opacity = '0';
    notification.style.transform = 'translateX(100%)';
    
    setTimeout(() => {
        notification.style.transition = 'all 0.3s ease';
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }
    }, 5000);
}

// Utility function to format text for PDF
function formatTextForPDF(text, maxLength = 100) {
    if (!text) return 'No information available';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Export functions for global access
window.generatePDF = generatePDF;
window.showNotification = showNotification;
