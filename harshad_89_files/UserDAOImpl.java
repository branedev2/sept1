package persistence.dao;

import java.util.List;

import org.hibernate.Session;
import org.hibernate.Transaction;

import persistence.MySessionFactory;
import persistence.User;

public class UserDAOImpl implements UserDAO {	 
	
	public UserDAOImpl() {
		
	}

	@Override
	public void create(User user) {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		Transaction tx = null;
		try {
			tx = session.beginTransaction();			
			session.save(user);
			tx.commit();
		 }
		 catch (Exception e) {
		    if (tx!=null) 
		    		tx.rollback();
		    throw e;
		 }
		 finally {
		     session.close();
		 }		 
	}

	@Override
	public void delete(User user) {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		Transaction tx = null;
		try {
			tx = session.beginTransaction();
			session.delete(user);
			tx.commit();
		 }
		 catch (Exception e) {
		    if (tx!=null) 
		    		tx.rollback();
		    throw e;
		 }
		 finally {
		     session.close();
		 }
	}

	@Override
	public int numberOfUsers() {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		int size = session.createSQLQuery("SELECT * FROM users").list().size();		 
	    session.close();
		return size;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<User> getUsers() {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		List<User> users = (List<User>) session.createSQLQuery("SELECT * FROM users").addEntity(User.class).list();
		session.close();
		return users;
	}

	@Override
	public User get(Integer id) {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		User user = (User) session.createSQLQuery("SELECT * FROM users where id = " + id).addEntity(User.class).uniqueResult();
		user.getPromotions().size();
		session.close();
		return user;
	}

	@Override
	public User get(String username) {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		User user = (User) session.createSQLQuery("SELECT * FROM users where username = '" + username + "'").addEntity(User.class).uniqueResult();		
		session.close();
		return user;	
	}	

	@Override
	public void update(User user) {
		// TODO Auto-generated method stub
		Session session = MySessionFactory.getSession();
		Transaction tx = null;
		try {
			tx = session.beginTransaction();
			session.saveOrUpdate(user);			
			tx.commit();
		 }
		 catch (Exception e) {
		    if (tx!=null) 
		    		tx.rollback();
		    throw e;
		 }
		 finally {
		     session.close();
		 }	
	}
}
