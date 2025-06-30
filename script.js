const HASHED_PASSKEY = "d3e515f78b195cce10be5014d9a10ef7276e28e99b91e4bbb08473590c9f557e";
let isAuthenticated = false;
let currentProduct = '';
let currentVersion = 'microsoft365';

// Office versions and their products
const officeVersions = {
    'microsoft365': [
        { id: 'O365ProPlusRetail', title: 'Microsoft 365 ProPlus', desc: 'Access, Excel, Teams, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-microsoft' },
        { id: 'O365AppsBasicRetail', title: 'Microsoft 365 Apps Basic', desc: 'Excel, OneNote, PowerPoint, Word, OneDrive', icon: 'bi-file-earmark-text' },
        { id: 'O365BusinessRetail', title: 'Microsoft 365 Business', desc: 'Access, Excel, Teams, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-briefcase' },
        { id: 'O365EduCloudRetail', title: 'Microsoft 365 Education', desc: 'Excel, OneNote, PowerPoint, Word, OneDrive, Teams', icon: 'bi-mortarboard' },
        { id: 'O365HomePremRetail', title: 'Microsoft 365 Home Premium', desc: 'Access, Excel, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-house' },
        { id: 'O365SmallBusPremRetail', title: 'Microsoft 365 Small Business Premium', desc: 'Access, Excel, Teams, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-building' },
        { id: 'ProjectProRetail', title: 'Project Professional', desc: 'Microsoft Project for project management', icon: 'bi-kanban' },
        { id: 'VisioProRetail', title: 'Visio Professional', desc: 'Visio for diagrams and flowcharts, OneDrive', icon: 'bi-diagram-3' }
    ],
    'office2024': [
        { id: 'ProPlus2024Retail', title: 'Office 2024 Professional Plus', desc: 'Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher', icon: 'bi-microsoft' },
        { id: 'HomeStudent2024Retail', title: 'Office 2024 Home & Student', desc: 'Word, Excel, PowerPoint, OneNote', icon: 'bi-mortarboard' },
        { id: 'HomeBusiness2024Retail', title: 'Office 2024 Home & Business', desc: 'Word, Excel, PowerPoint, Outlook, OneNote', icon: 'bi-briefcase' }
    ],
    'office2021': [
        { id: 'ProPlus2021Retail', title: 'Office 2021 Professional Plus', desc: 'Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher', icon: 'bi-microsoft' },
        { id: 'HomeStudent2021Retail', title: 'Office 2021 Home & Student', desc: 'Word, Excel, PowerPoint, OneNote', icon: 'bi-mortarboard' },
        { id: 'HomeBusiness2021Retail', title: 'Office 2021 Home & Business', desc: 'Word, Excel, PowerPoint, Outlook, OneNote', icon: 'bi-briefcase' },
        { id: 'Professional2021Retail', title: 'Office 2021 Professional', desc: '	Access, Excel, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-briefcase' }
    ],
    'office2019': [
        { id: 'ProPlus2019Retail', title: 'Office 2019 Professional Plus', desc: 'Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher', icon: 'bi-microsoft' },
        { id: 'HomeStudent2019Retail', title: 'Office 2019 Home & Student', desc: 'Word, Excel, PowerPoint, OneNote', icon: 'bi-mortarboard' },
        { id: 'HomeBusiness2019Retail', title: 'Office 2019 Home & Business', desc: 'Word, Excel, PowerPoint, Outlook, OneNote', icon: 'bi-briefcase' },
        { id: 'Professional2019Retail', title: 'Office 2019 Professional', desc: '	Access, Excel, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-briefcase' }
    ],
    'office2016': [
        { id: 'ProPlus2016Retail', title: 'Office 2016 Professional Plus', desc: 'Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher', icon: 'bi-microsoft' },
        { id: 'HomeStudent2016Retail', title: 'Office 2016 Home & Student', desc: 'Word, Excel, PowerPoint, OneNote', icon: 'bi-mortarboard' },
        { id: 'HomeBusiness2016Retail', title: 'Office 2016 Home & Business', desc: 'Word, Excel, PowerPoint, Outlook, OneNote', icon: 'bi-briefcase' },
        { id: 'Professional2016Retail', title: 'Office 2016 Professional', desc: '	Access, Excel, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-briefcase' }
    ],
    'office2013': [
        { id: 'ProPlus2013Retail', title: 'Office 2013 Professional Plus', desc: 'Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher', icon: 'bi-microsoft' },
        { id: 'HomeStudent2013Retail', title: 'Office 2013 Home & Student', desc: 'Word, Excel, PowerPoint, OneNote', icon: 'bi-mortarboard' },
        { id: 'HomeBusiness2013Retail', title: 'Office 2013 Home & Business', desc: 'Word, Excel, PowerPoint, Outlook, OneNote', icon: 'bi-briefcase' },
        { id: 'Professional2013Retail', title: 'Office 2013 Professional', desc: '	Access, Excel, OneNote, Outlook, PowerPoint, Publisher, Word, OneDrive', icon: 'bi-briefcase' }
    ]
};

// Download links for Office versions
const downloadLinks = {
    // Microsoft 365
    'O365ProPlusRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365ProPlusRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365ProPlusRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/O365ProPlusRetail.img'
    },
    'O365AppsBasicRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365AppsBasicRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365AppsBasicRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': null
    },
    'O365BusinessRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365BusinessRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365BusinessRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/O365BusinessRetail.img'
    },
    'O365EduCloudRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365EduCloudRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365EduCloudRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': null
    },
    'O365HomePremRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365HomePremRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365HomePremRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/O365HomePremRetail.img'
    },
    'O365SmallBusPremRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365SmallBusPremRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365SmallBusPremRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': null
    },
    'ProjectProRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProjectProRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProjectProRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProjectProRetail.img'
    },
    'VisioProRetail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=VisioProRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=VisioProRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/VisioProRetail.img'
    },

    // Office 2024
    'ProPlus2024Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlus2024Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlus2024Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProPlus2024Retail.img'
    },
    'HomeStudent2024Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=Home2024Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=Home2024Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/Home2024Retail.img'
    },
    'HomeBusiness2024Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusiness2024Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusiness2024Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeBusiness2024Retail.img'
    },

    // Office 2021
    'ProPlus2021Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlus2021Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlus2021Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProPlus2021Retail.img'
    },
    'HomeStudent2021Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudent2021Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudent2021Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeStudent2021Retail.img'
    },
    'HomeBusiness2021Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusiness2021Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusiness2021Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeBusiness2021Retail.img'
    },

    'Professional2021Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=Professional2021Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=Professional2021Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/Professional2021Retail.img'
    },

    // Office 2019
    'ProPlus2019Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlus2019Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlus2019Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProPlus2019Retail.img'
    },
    'HomeStudent2019Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudent2019Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudent2019Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeStudent2019Retail.img'
    },
    'HomeBusiness2019Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusiness2019Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusiness2019Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeBusiness2019Retail.img'
    },

    'Professional2019Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=Professional2019Retail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=Professional2019Retail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/Professional2019Retail.img'
    },

    // Office 2016
    'ProPlus2016Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlusRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlusRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProPlusRetail.img'
    },
    'HomeStudent2016Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudentRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudentRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeStudentRetail.img'
    },
    'HomeBusiness2016Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusinessRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusinessRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeBusinessRetail.img'
    },

    'Professional2016Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProfessionalRetail&platform=x64&language=en-us&version=O16GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProfessionalRetail&platform=x86&language=en-us&version=O16GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProfessionalRetail.img'
    },

    // Office 2013
    'ProPlus2013Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlusRetail&platform=x64&language=en-us&version=O15GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProPlusRetail&platform=x86&language=en-us&version=O15GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/ProPlus2013Retail.img'
    },
    'HomeStudent2013Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudentRetail&platform=x64&language=en-us&version=O15GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeStudentRetail&platform=x86&language=en-us&version=O15GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/492350f6-3a01-4f97-b9c0-c7c6ddf67d60/media/en-us/HomeStudent2013Retail.img'
    },
    'HomeBusiness2013Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusinessRetail&platform=x64&language=en-us&version=O15GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=HomeBusinessRetail&platform=x86&language=en-us&version=O15GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/39168d7e-077b-48e7-872c-b232c3e72675/media/en-us/HomeBusinessRetail.img'
    },

    'Professional2013Retail': {
        'online-x64': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProfessionalRetail&platform=x64&language=en-us&version=O15GA',
        'online-x32': 'https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=ProfessionalRetail&platform=x86&language=en-us&version=O15GA',
        'offline-x32-x64': 'https://officecdn.microsoft.com/db/39168d7e-077b-48e7-872c-b232c3e72675/media/en-us/ProfessionalRetail.img'
    }
};

function switchVersion(version) {
    currentVersion = version;
    
    // Update active tab
    document.querySelectorAll('.version-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Load products for selected version
    loadProducts(version);
}

function loadProducts(version) {
    const container = document.getElementById('office-versions');
    const products = officeVersions[version] || [];
    
    container.innerHTML = '';
    
    products.forEach((product, index) => {
        const productCard = document.createElement('div');
        productCard.className = 'col-lg-4 col-md-6 fade-in';
        productCard.style.animationDelay = `${index * 0.1}s`;
        
        productCard.innerHTML = `
            <div class="office-card card h-100 p-4 text-center" onclick="showDownloadOptions('${product.id}')">
                <div class="card-body">
                    <i class="${product.icon} display-4 text-primary mb-3"></i>
                    <h5 class="card-title fw-bold">${product.title}</h5>
                    <p class="card-text text-muted small mb-4">${product.desc}</p>
                    <button class="btn download-btn text-white w-100">
                        <i class="bi bi-download me-2"></i>Select Download
                    </button>
                </div>
            </div>
        `;
        
        container.appendChild(productCard);
    });
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    loadProducts('microsoft365');
});

function openModal() {
    const modal = new bootstrap.Modal(document.getElementById('passkeyModal'));
    modal.show();
    setTimeout(() => document.getElementById('passkey').focus(), 500);
}

function showDownloadOptions(productId) {
    if (!isAuthenticated) {
        const toast = document.createElement('div');
        toast.className = 'toast-container position-fixed top-0 end-0 p-3';
        toast.innerHTML = `
            <div class="toast show align-items-center text-bg-warning" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="bi bi-exclamation-triangle me-2"></i>Please verify your passkey first!
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
        return;
    }

    currentProduct = productId;
    const productName = productId.replace(/([A-Z])/g, ' $1').trim().replace(/\b\w/g, l => l.toUpperCase());
    document.getElementById('downloadTitle').textContent = productName;
    
    // Show/hide offline option
    const offlineOption = document.getElementById('offlineOption');
    const hasOfflineOption = downloadLinks[productId] && downloadLinks[productId]['offline-x32-x64'];
    offlineOption.style.display = hasOfflineOption ? 'block' : 'none';
    
    const modal = new bootstrap.Modal(document.getElementById('downloadModal'));
    modal.show();
}

async function verifyPasskey(event) {
    event.preventDefault();
    const passkeyInput = document.getElementById('passkey');
    const verifyBtn = document.getElementById('verifyBtn');
    const successMessage = document.getElementById('successMessage');
    const errorMessage = document.getElementById('errorMessage');
    
    // Show loading state
    verifyBtn.innerHTML = '<span class="loading-spinner me-2"></span>Verifying...';
    verifyBtn.disabled = true;
    
    // Hide previous messages
    successMessage.style.display = 'none';
    errorMessage.style.display = 'none';
    
    // Simulate verification delay
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Hash the input passkey
    const inputPasskey = passkeyInput.value;
    const hashedInput = await hashString(inputPasskey);
    
    if (hashedInput === HASHED_PASSKEY) {
        isAuthenticated = true;
        successMessage.style.display = 'block';
        document.getElementById('commandSection').style.display = 'block';
        
        setTimeout(() => {
            bootstrap.Modal.getInstance(document.getElementById('passkeyModal')).hide();
            passkeyInput.value = '';
        }, 2000);
    } else {
        errorMessage.style.display = 'block';
        passkeyInput.value = '';
        passkeyInput.focus();
    }
    
    // Reset button
    verifyBtn.innerHTML = '<i class="bi bi-check-circle me-2"></i>Verify & Continue';
    verifyBtn.disabled = false;
}

async function hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function downloadOffice(type) {
    const downloadUrl = downloadLinks[currentProduct] && downloadLinks[currentProduct][type];
    
    if (!downloadUrl) {
        // Create a dummy download for demonstration
        const fileName = `${currentProduct}_${type}.exe`;
        showDownloadProgress(fileName);
        return;
    }
    
    // Create download link
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = '';
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Show download notification
    showDownloadNotification();
}

function showDownloadProgress(fileName) {
    const modal = bootstrap.Modal.getInstance(document.getElementById('downloadModal'));
    modal.hide();
    
    // Create progress toast
    const toast = document.createElement('div');
    toast.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    toast.innerHTML = `
        <div class="toast show align-items-center text-bg-primary" role="alert">
            <div class="d-flex w-100">
                <div class="toast-body flex-grow-1">
                    <div class="d-flex align-items-center">
                        <span class="loading-spinner me-2"></span>
                        <div>
                            <strong>Downloading ${fileName}</strong>
                            <div class="progress mt-1" style="height: 4px;">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                        role="progressbar" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    document.body.appendChild(toast);
    
    // Simulate progress
    const progressBar = toast.querySelector('.progress-bar');
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            setTimeout(() => {
                toast.remove();
                showDownloadComplete(fileName);
            }, 500);
        }
        progressBar.style.width = progress + '%';
    }, 200);
}

function showDownloadComplete(fileName) {
    const toast = document.createElement('div');
    toast.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    toast.innerHTML = `
        <div class="toast show align-items-center text-bg-success" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="bi bi-check-circle me-2"></i>
                    <strong>${fileName}</strong> downloaded successfully!
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

function showDownloadNotification() {
    const toast = document.createElement('div');
    toast.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    toast.innerHTML = `
        <div class="toast show align-items-center text-bg-info" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="bi bi-download me-2"></i>Download started! Check your Downloads folder.
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function copyCommand() {
    const command = document.getElementById('activationCommand').textContent;
    navigator.clipboard.writeText(command).then(() => {
        const copyBtn = document.querySelector('.copy-btn');
        const originalText = copyBtn.innerHTML;
        copyBtn.innerHTML = '<i class="bi bi-check me-1"></i>Copied!';
        copyBtn.classList.add('btn-success');
        copyBtn.classList.remove('copy-btn');
        
        setTimeout(() => {
            copyBtn.innerHTML = originalText;
            copyBtn.classList.remove('btn-success');
            copyBtn.classList.add('copy-btn');
        }, 2000);
    });
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        const modals = document.querySelectorAll('.modal.show');
        modals.forEach(modal => {
            bootstrap.Modal.getInstance(modal).hide();
        });
    }
});

// Add smooth scrolling for better UX
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});