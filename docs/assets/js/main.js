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

    // Carousel functionality - Laracasts style
    const carouselTrack = document.querySelector('.carousel-track');
    const prevBtn = document.querySelector('.carousel-btn.prev');
    const nextBtn = document.querySelector('.carousel-btn.next');
    const cards = document.querySelectorAll('.carousel-card');
    const carouselContainer = document.querySelector('.carousel-container');

    if (carouselTrack && cards.length > 0) {
        let currentIndex = 0;
        let autoplayInterval = null;
        let isPaused = false;

        // Get gap from container
        function getGap() {
            const style = window.getComputedStyle(carouselTrack);
            const gap = style.gap || style.gridGap || '32px';
            return parseInt(gap) || 32;
        }

        // Calculate how many cards are fully visible
        function getVisibleCards() {
            const containerWidth = carouselContainer.offsetWidth;
            const cardWidth = cards[0].offsetWidth;
            const gap = getGap();
            const totalCardWidth = cardWidth + gap;
            return Math.max(1, Math.floor((containerWidth + gap) / totalCardWidth));
        }

        // Get max index - ensures we can always scroll at least a bit
        function getMaxIndex() {
            const visible = getVisibleCards();
            const maxIdx = cards.length - visible;
            // Ensure we always have at least 2 positions to scroll through
            return Math.max(1, maxIdx);
        }

        // Move carousel
        function goToSlide(index) {
            const maxIndex = getMaxIndex();
            
            if (index < 0) {
                currentIndex = maxIndex;
            } else if (index > maxIndex) {
                currentIndex = 0;
            } else {
                currentIndex = index;
            }

            const cardWidth = cards[0].offsetWidth;
            const gap = getGap();
            const offset = currentIndex * (cardWidth + gap);
            
            carouselTrack.style.transform = `translateX(-${offset}px)`;
        }

        function nextSlide() {
            goToSlide(currentIndex + 1);
        }

        function prevSlide() {
            goToSlide(currentIndex - 1);
        }

        // Autoplay
        function startAutoplay() {
            stopAutoplay();
            autoplayInterval = setInterval(() => {
                if (!isPaused) {
                    nextSlide();
                }
            }, 3000);
        }

        function stopAutoplay() {
            if (autoplayInterval) {
                clearInterval(autoplayInterval);
                autoplayInterval = null;
            }
        }

        // Initialize autoplay
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
                startAutoplay();
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                nextSlide();
                stopAutoplay();
                startAutoplay();
            });
        }

        // Handle window resize
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                const maxIndex = getMaxIndex();
                if (currentIndex > maxIndex) {
                    currentIndex = maxIndex;
                }
                goToSlide(currentIndex);
            }, 100);
        });

        // Touch/swipe support
        let touchStartX = 0;
        let touchEndX = 0;

        carouselTrack.addEventListener('touchstart', (e) => {
            touchStartX = e.changedTouches[0].screenX;
            isPaused = true;
        }, { passive: true });

        carouselTrack.addEventListener('touchend', (e) => {
            touchEndX = e.changedTouches[0].screenX;
            isPaused = false;
            handleSwipe();
        }, { passive: true });

        function handleSwipe() {
            const swipeThreshold = 50;
            const diff = touchStartX - touchEndX;

            if (Math.abs(diff) > swipeThreshold) {
                if (diff > 0) {
                    nextSlide();
                } else {
                    prevSlide();
                }
            }
        }
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
