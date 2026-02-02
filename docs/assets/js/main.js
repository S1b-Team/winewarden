// WineWarden Jekyll Site JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Mobile navigation toggle
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    
    if (navToggle) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }
    
    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
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
    
    // Navbar background on scroll
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(15, 23, 42, 0.98)';
        } else {
            navbar.style.background = 'rgba(15, 23, 42, 0.95)';
        }
    });
    
    // Fade in animation on scroll
    const fadeElements = document.querySelectorAll('.culture-card, .feature-card, .install-card');
    
    const fadeObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });
    
    fadeElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        fadeObserver.observe(el);
    });

    // Carousel functionality
    const carouselTrack = document.querySelector('.carousel-track');
    const prevBtn = document.querySelector('.carousel-btn.prev');
    const nextBtn = document.querySelector('.carousel-btn.next');
    const cards = document.querySelectorAll('.carousel-card');
    const carouselContainer = document.querySelector('.carousel-container');

    if (carouselTrack && cards.length > 0) {
        let currentIndex = 0;
        const cardWidth = 350 + 32; // card width + gap
        const maxIndex = Math.max(0, cards.length - Math.floor(window.innerWidth / cardWidth));
        let autoplayInterval;
        let isPaused = false;

        function updateCarousel() {
            carouselTrack.style.transform = `translateX(-${currentIndex * cardWidth}px)`;
        }

        function nextSlide() {
            if (currentIndex < maxIndex) {
                currentIndex++;
            } else {
                currentIndex = 0; // Loop back to start
            }
            updateCarousel();
        }

        function prevSlide() {
            if (currentIndex > 0) {
                currentIndex--;
            } else {
                currentIndex = maxIndex; // Loop to end
            }
            updateCarousel();
        }

        // Autoplay functionality
        function startAutoplay() {
            autoplayInterval = setInterval(() => {
                if (!isPaused) {
                    nextSlide();
                }
            }, 3000); // Change slide every 3 seconds
        }

        function stopAutoplay() {
            clearInterval(autoplayInterval);
        }

        // Start autoplay
        startAutoplay();

        // Pause on hover
        if (carouselContainer) {
            carouselContainer.addEventListener('mouseenter', () => {
                isPaused = true;
            });

            carouselContainer.addEventListener('mouseleave', () => {
                isPaused = false;
            });
        }

        // Button controls
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                prevSlide();
                stopAutoplay();
                startAutoplay(); // Reset timer
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                nextSlide();
                stopAutoplay();
                startAutoplay(); // Reset timer
            });
        }

        // Touch/swipe support
        let startX = 0;
        let isDragging = false;

        carouselTrack.addEventListener('touchstart', (e) => {
            startX = e.touches[0].clientX;
            isDragging = true;
            isPaused = true; // Pause while touching
        });

        carouselTrack.addEventListener('touchmove', (e) => {
            if (!isDragging) return;
        });

        carouselTrack.addEventListener('touchend', (e) => {
            if (!isDragging) return;
            isDragging = false;
            isPaused = false; // Resume after touch

            const endX = e.changedTouches[0].clientX;
            const diff = startX - endX;

            if (Math.abs(diff) > 50) {
                if (diff > 0 && currentIndex < maxIndex) {
                    currentIndex++;
                } else if (diff < 0 && currentIndex > 0) {
                    currentIndex--;
                }
                updateCarousel();
            }
        });
    }
});

// Copy code to clipboard
function copyCode(button) {
    const codeBlock = button.previousElementSibling;
    const code = codeBlock.querySelector('code').textContent;
    
    navigator.clipboard.writeText(code).then(() => {
        const originalIcon = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i>';
        button.style.color = '#00ff88';
        
        setTimeout(() => {
            button.innerHTML = originalIcon;
            button.style.color = '';
        }, 2000);
    });
}
