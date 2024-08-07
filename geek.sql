-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: Serenity
-- ------------------------------------------------------
-- Server version	8.0.36-0ubuntu0.20.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `comments`
--

DROP TABLE IF EXISTS `comments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `comments` (
  `id` int NOT NULL AUTO_INCREMENT,
  `post_id` int NOT NULL,
  `author_id` int NOT NULL,
  `body` text NOT NULL,
  `created` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `author_id` (`author_id`),
  KEY `fk_post_id` (`post_id`),
  CONSTRAINT `comments_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `comments_ibfk_2` FOREIGN KEY (`author_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_post_id` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `comments`
--

LOCK TABLES `comments` WRITE;
/*!40000 ALTER TABLE `comments` DISABLE KEYS */;
INSERT INTO `comments` VALUES (1,2,1,'Long form text actually works and displays nicely, with images','2024-04-24 09:26:26'),(3,3,1,'new comment by the blog author','2024-04-29 15:31:00');
/*!40000 ALTER TABLE `comments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `post_tags`
--

DROP TABLE IF EXISTS `post_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `post_tags` (
  `post_id` int NOT NULL,
  `tag_id` int NOT NULL,
  PRIMARY KEY (`post_id`,`tag_id`),
  KEY `tag_id` (`tag_id`),
  CONSTRAINT `post_tags_ibfk_1` FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `post_tags_ibfk_2` FOREIGN KEY (`tag_id`) REFERENCES `tags` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `post_tags`
--

LOCK TABLES `post_tags` WRITE;
/*!40000 ALTER TABLE `post_tags` DISABLE KEYS */;
INSERT INTO `post_tags` VALUES (2,2),(4,4),(3,6),(6,7);
/*!40000 ALTER TABLE `post_tags` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `posts`
--

DROP TABLE IF EXISTS `posts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `posts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(256) NOT NULL,
  `body` text NOT NULL,
  `author_id` int NOT NULL,
  `created` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `status` varchar(50) NOT NULL,
  `image` varchar(256) DEFAULT NULL,
  `like_count` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `author_id` (`author_id`),
  CONSTRAINT `posts_ibfk_1` FOREIGN KEY (`author_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `posts`
--

LOCK TABLES `posts` WRITE;
/*!40000 ALTER TABLE `posts` DISABLE KEYS */;
INSERT INTO `posts` VALUES (2,'Long Form Post','Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam convallis tempus turpis, ac consequat justo venenatis nec. Sed mi diam, vestibulum quis venenatis quis, suscipit nec dolor. In feugiat sapien et purus sollicitudin finibus. Aenean imperdiet eros id sem dignissim, id efficitur dolor malesuada. Integer eu elit sodales nibh fringilla efficitur. Mauris gravida semper blandit. Phasellus non lorem tortor. Morbi eu ornare eros. Duis efficitur, libero sit amet efficitur laoreet, nibh ex consequat tortor, sit amet cursus orci est sit amet felis. Maecenas tempus finibus quam eu laoreet. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Quisque malesuada, arcu nec blandit ornare, eros nibh aliquam nunc, vitae gravida risus ex at eros. Maecenas nunc arcu, volutpat in semper vel, elementum non eros. Duis vitae sollicitudin ipsum.\r\n\r\nMaecenas quis cursus velit, consequat interdum lorem. Praesent imperdiet commodo massa sed consectetur. Nam ornare ipsum id vehicula suscipit. Integer venenatis facilisis nisl non rhoncus. Etiam porttitor rutrum velit eget dignissim. Etiam eleifend semper quam ac blandit. Nulla vitae leo iaculis, tempor leo vitae, fermentum urna. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Suspendisse quam leo, egestas nec felis at, aliquam varius enim. Aliquam erat volutpat. Integer facilisis purus est.\r\n\r\nNullam maximus eget nibh vitae euismod. Fusce ut viverra metus, sit amet ornare ligula. Vivamus sit amet vulputate nibh. In ultricies purus enim, quis imperdiet tortor volutpat et. Nam scelerisque dui a elementum semper. Quisque dapibus est sed risus maximus tempor. Suspendisse potenti. Duis interdum neque et odio laoreet, nec convallis enim luctus. In hac habitasse platea dictumst. Donec dignissim, lacus vitae porttitor porta, enim mi bibendum nulla, eu vulputate metus nibh at nisi. Quisque eu euismod risus. Aliquam facilisis cursus sapien et posuere. Phasellus iaculis eleifend libero. Nunc pretium fringilla augue, sed ullamcorper arcu auctor nec. Pellentesque eu tincidunt lectus, quis aliquet velit.\r\n\r\nCras vel varius quam, et finibus massa. In euismod et nisl maximus lobortis. Quisque consectetur magna diam, ut venenatis ante ornare vitae. Phasellus hendrerit non lacus ac faucibus. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse sagittis dui diam, id faucibus quam posuere vitae. Phasellus ante lorem, ultrices vitae sapien nec, tristique vestibulum dui. Aliquam eu tortor at purus molestie varius. Nunc dictum, nulla in imperdiet tempus, enim erat gravida massa, vel suscipit tortor nibh eu neque. Phasellus sit amet arcu eget urna hendrerit accumsan vel at arcu. Nunc mattis turpis metus, eget egestas nisl tempus quis. Morbi sit amet urna ac libero consectetur mattis. Mauris et egestas ante, eu imperdiet nibh.\r\n\r\nIn eu tempor dui. Cras eu tincidunt velit. Sed non ante rutrum, eleifend arcu nec, tempus ipsum. Sed at hendrerit erat, ac euismod nisi. Praesent eget erat accumsan, convallis sapien at, viverra risus. Sed hendrerit, leo et elementum dapibus, lacus libero egestas lectus, vel rutrum velit sapien nec augue. Nam non lacus ac quam blandit fringilla. Ut eleifend lobortis magna, ut imperdiet nisi volutpat sit amet. ',1,'2024-04-24 09:24:46','published','public/20231111.jpg',0),(3,'The Art of Mindful Coding',' Learn how to code with clarity and focus, incorporating mindfulness practices into your programming routine.',1,'2024-04-29 15:12:37','published','public/meditation.avif',0),(4,'Digital Serenity: Strategies for Mental Clarity Amidst Distractions',' Explore strategies for maintaining mental clarity and calmness in the midst of digital distractions\r\n\r\nIn our fast-paced, hyper-connected world, maintaining mental clarity and calmness can feel like an elusive quest. The constant barrage of notifications, emails, social media updates, and work demands can overwhelm our minds, leaving us feeling mentally foggy and drained. But fear not! Here are some effective strategies to help you navigate the digital noise and find your mental sweet spot:\r\n\r\n1. Understand Mental Clarity\r\nBefore we dive into strategies, let’s define what mental clarity means. It’s more than just the absence of confusion. Mental clarity is a specific state where your mind feels sharp, thoughts are clear, and focus remains undivided. When you’re mentally clear, creativity flows, problems find solutions, and tasks get done efficiently. It’s like having a superpower in today’s chaotic world.\r\n\r\n2. Prioritize Sleep and Nutrition\r\nSleep: Lack of sleep impairs cognitive function. Aim for 7-9 hours of quality sleep each night. Create a calming bedtime routine, avoid screens before bed, and keep your sleep environment conducive to rest.\r\nNutrition: Feed your brain with nutrient-rich foods. Omega-3 fatty acids, antioxidants, and whole grains support mental clarity. Stay hydrated and limit sugar and processed foods.\r\n\r\n3. Tame Information Overload\r\nDigital Detox: Regularly disconnect from screens. Set boundaries for checking emails and social media. Consider tech-free weekends or evenings.\r\nMindful Consumption: Be intentional about what you consume online. Curate your feeds to include positive, informative content. Unfollow accounts that drain your energy.\r\n\r\n4. Move Your Body\r\nExercise: Physical activity boosts mental clarity. Whether it’s a brisk walk, yoga, or dancing, find what works for you. Exercise increases blood flow to the brain and reduces stress.\r\nNature Breaks: Step outside and breathe fresh air. Nature has a calming effect on our minds. Even a few minutes in a park can make a difference.\r\n\r\n5. Practice Mindfulness\r\nMeditation: Regular meditation cultivates mental clarity. Set aside time each day to sit quietly, focus on your breath, and let go of distractions.\r\nMindful Eating: Pay attention to your meals. Chew slowly, savor flavors, and be present. Avoid eating while multitasking.\r\n\r\n6. Declutter Your Environment\r\nDigital Space: Organize your digital files, emails, and apps. Delete what you don’t need. A clutter-free digital environment reduces mental noise.\r\nPhysical Space: Keep your workspace tidy. Clear surfaces lead to a clearer mind.\r\n\r\n7. Take Breaks\r\nPomodoro Technique: Work in focused bursts (e.g., 25 minutes) followed by short breaks. Use a timer to stay disciplined.\r\nRestorative Breaks: Step away from screens. Close your eyes, breathe deeply, or visualize a peaceful place.\r\n\r\n8. Reflect and Write\r\nJournaling: Write down your thoughts, feelings, and experiences. Reflect on positive moments. Capture insights and lessons learned.\r\nPositive Imagery: Close your eyes and imagine a serene place. Describe it in detail. Revisit this mental oasis during chaotic times.',1,'2024-04-29 18:10:36','published','public/zen2.jpg',0),(6,'New Zen','Try something different ',2,'2024-04-30 07:42:58','published','public/IMG-20240429-WA0015.jpg',0),(15,'gjhlk','kjhkjkjklj',1,'2024-05-01 22:45:23','published',NULL,0);
/*!40000 ALTER TABLE `posts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tags`
--

DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tags` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(256) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tags`
--

LOCK TABLES `tags` WRITE;
/*!40000 ALTER TABLE `tags` DISABLE KEYS */;
INSERT INTO `tags` VALUES (2,''),(3,'burnout'),(7,'burnout '),(6,'health'),(8,'Mental Health'),(1,'Tag'),(5,'wellness'),(4,'worklife');
/*!40000 ALTER TABLE `tags` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(512) DEFAULT NULL,
  `first_name` varchar(50) DEFAULT NULL,
  `last_name` varchar(50) DEFAULT NULL,
  `date_of_birth` date DEFAULT NULL,
  `bio` text,
  `avatar` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'Changamire','tmasaire@yahoo.com','scrypt:32768:8:1$gIMS8rL7gVBiM2Wa$0b94cf1bd05c2d8db2aacffba90208110fb51e4fdca9b2290c9d993d219a307a1204ddd5a6eb6cfa6794754d8c9e2304b4cb504adc69b3fd69f0c23878c4bb87',NULL,NULL,NULL,NULL,NULL),(2,'Zen','taumasaire@gmail.com','scrypt:32768:8:1$uabNoWHx93U1KZOX$90935ae0d38ce5dd1fad3d3386505683ad951096f46b0ba7c60b215fcaff08b02c7677bb3814546b1ffed959c17cbcd4bcd44c01070d44a05d1a5b4d3880cfd2',NULL,NULL,NULL,NULL,NULL),(3,'Aevy','Smithavery@gmail.com','scrypt:32768:8:1$VFPqubXRRyRhVuEm$996af1ce552ac7271a25488ec440ef2dec4ad6c47372f07993546c8357e69b42a366a1118d1eacc288bc242fe0ca278d42afe57bcf74320e445709f98f946837',NULL,NULL,NULL,NULL,NULL),(4,'Changa','hhjhjh','scrypt:32768:8:1$P5ztGj89S85stxEY$0d57f60a0020316df66b94f2911812ed49a05e130fa4b7389cfe6a104f43559d03a20f61f724f7d07651fe49c24ac39040129ee031ab612a250789b479d7f36d',NULL,NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-05-03 13:43:18
