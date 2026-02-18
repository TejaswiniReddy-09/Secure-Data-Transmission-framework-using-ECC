// Main JavaScript functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // File upload drag and drop
    initializeFileUploads();
    
    // Form validation
    initializeFormValidation();
    
    // Performance charts
    initializePerformanceCharts();
});

function initializeFileUploads() {
    const fileAreas = document.querySelectorAll('.file-upload-area');
    
    fileAreas.forEach(area => {
        const input = area.querySelector('input[type="file"]');
        
        area.addEventListener('click', () => input.click());
        
        area.addEventListener('dragover', (e) => {
            e.preventDefault();
            area.classList.add('dragover');
        });
        
        area.addEventListener('dragleave', () => {
            area.classList.remove('dragover');
        });
        
        area.addEventListener('drop', (e) => {
            e.preventDefault();
            area.classList.remove('dragover');
            
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                updateFileLabel(area, e.dataTransfer.files[0].name);
            }
        });
        
        input.addEventListener('change', () => {
            if (input.files.length) {
                updateFileLabel(area, input.files[0].name);
            }
        });
    });
}

function updateFileLabel(area, filename) {
    const label = area.querySelector('.file-upload-label');
    if (label) {
        label.textContent = filename;
        label.classList.add('text-success');
    }
}

function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let valid = true;
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    valid = false;
                    field.classList.add('is-invalid');
                } else {
                    field.classList.remove('is-invalid');
                }
            });
            
            if (!valid) {
                e.preventDefault();
                showAlert('Please fill in all required fields.', 'danger');
            }
        });
    });
}

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

function initializePerformanceCharts() {
    const ctx = document.getElementById('performanceChart');
    if (ctx) {
        fetch('/get_operations')
            .then(response => response.json())
            .then(data => {
                if (!data.error) {
                    createPerformanceChart(ctx, data);
                }
            })
            .catch(error => console.error('Error loading chart data:', error));
    }
}

function createPerformanceChart(ctx, data) {
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.algorithms,
            datasets: [
                {
                    label: 'Encryption Time (s)',
                    data: data.encryption_times,
                    backgroundColor: 'rgba(255, 107, 53, 0.8)',
                    borderColor: 'rgba(255, 107, 53, 1)',
                    borderWidth: 1
                },
                {
                    label: 'Decryption Time (s)',
                    data: data.decryption_times,
                    backgroundColor: 'rgba(243, 156, 18, 0.8)',
                    borderColor: 'rgba(243, 156, 18, 1)',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Performance Comparison'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Time (seconds)'
                    }
                }
            }
        }
    });
}

// Utility functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Export for use in other modules
window.ECCSteganography = {
    showAlert,
    formatFileSize,
    debounce
};